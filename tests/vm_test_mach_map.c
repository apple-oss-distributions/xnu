/* Mach vm map miscellaneous unit tests
 *
 * This test program serves to be a regression test suite for legacy
 * vm issues, ideally each test will be linked to a radar number and
 * perform a set of certain validations.
 *
 */
#include <darwintest.h>
#include <darwintest_utils.h>
#include "try_read_write.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <ptrauth.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <mach/mach_error.h>
#include <mach/mach_host.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/vm_param.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/shared_region.h>
#include <machine/cpu_capabilities.h>

#include <sys/mman.h>
#include <sys/syslimits.h>

#include <mach-o/dyld.h>

#if __has_include(<os/security_config_private.h>)
#import <os/security_config_private.h>     // for os_security_config_get()
#endif /* __has_include(<os/security_config_private.h>) */

#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true));

static void
test_memory_entry_tagging(int override_tag)
{
	int                     pass;
	int                     do_copy;
	kern_return_t           kr;
	mach_vm_address_t       vmaddr_orig, vmaddr_shared, vmaddr_copied;
	mach_vm_size_t          vmsize_orig, vmsize_shared, vmsize_copied;
	mach_vm_address_t       *vmaddr_ptr;
	mach_vm_size_t          *vmsize_ptr;
	mach_vm_address_t       vmaddr_chunk;
	mach_vm_size_t          vmsize_chunk;
	mach_vm_offset_t        vmoff;
	mach_port_t             mem_entry_copied, mem_entry_shared;
	mach_port_t             *mem_entry_ptr;
	unsigned int            i;
	vm_region_submap_short_info_data_64_t ri;
	mach_msg_type_number_t  ri_count;
	unsigned int            depth;
	int                     vm_flags;
	unsigned int            expected_tag;

	vmaddr_copied = 0;
	vmaddr_shared = 0;
	vmsize_copied = 0;
	vmsize_shared = 0;
	vmaddr_chunk = 0;
	vmsize_chunk = 16 * 1024;
	vmaddr_orig = 0;
	vmsize_orig = 3 * vmsize_chunk;
	mem_entry_copied = MACH_PORT_NULL;
	mem_entry_shared = MACH_PORT_NULL;
	pass = 0;

	vmaddr_orig = 0;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr_orig,
	    vmsize_orig,
	    VM_FLAGS_ANYWHERE);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "[override_tag:%d] vm_allocate(%lld)",
	    override_tag, vmsize_orig);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	for (i = 0; i < vmsize_orig / vmsize_chunk; i++) {
		vmaddr_chunk = vmaddr_orig + ((mach_vm_size_t)i * vmsize_chunk);
		kr = mach_vm_allocate(mach_task_self(),
		    &vmaddr_chunk,
		    vmsize_chunk,
		    (VM_FLAGS_FIXED |
		    VM_FLAGS_OVERWRITE |
		    VM_MAKE_TAG(100 + (int)i)));
		T_QUIET;
		T_EXPECT_MACH_SUCCESS(kr, "[override_tag:%d] vm_allocate(%lld)",
		    override_tag, vmsize_chunk);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
	}

	for (vmoff = 0;
	    vmoff < vmsize_orig;
	    vmoff += PAGE_SIZE) {
		*((unsigned char *)(uintptr_t)(vmaddr_orig + vmoff)) = 'x';
	}

	do_copy = time(NULL) & 1;
again:
	*((unsigned char *)(uintptr_t)vmaddr_orig) = 'x';
	if (do_copy) {
		mem_entry_ptr = &mem_entry_copied;
		vmsize_copied = vmsize_orig;
		vmsize_ptr = &vmsize_copied;
		vmaddr_copied = 0;
		vmaddr_ptr = &vmaddr_copied;
		vm_flags = MAP_MEM_VM_COPY;
	} else {
		mem_entry_ptr = &mem_entry_shared;
		vmsize_shared = vmsize_orig;
		vmsize_ptr = &vmsize_shared;
		vmaddr_shared = 0;
		vmaddr_ptr = &vmaddr_shared;
		vm_flags = MAP_MEM_VM_SHARE;
	}
	kr = mach_make_memory_entry_64(mach_task_self(),
	    vmsize_ptr,
	    vmaddr_orig,                            /* offset */
	    (vm_flags |
	    VM_PROT_READ | VM_PROT_WRITE),
	    mem_entry_ptr,
	    MACH_PORT_NULL);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "[override_tag:%d][do_copy:%d] mach_make_memory_entry()",
	    override_tag, do_copy);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}
	T_QUIET;
	T_EXPECT_EQ(*vmsize_ptr, vmsize_orig, "[override_tag:%d][do_copy:%d] vmsize (0x%llx) != vmsize_orig (0x%llx)",
	    override_tag, do_copy, (uint64_t) *vmsize_ptr, (uint64_t) vmsize_orig);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}
	T_QUIET;
	T_EXPECT_NOTNULL(*mem_entry_ptr, "[override_tag:%d][do_copy:%d] mem_entry == 0x%x",
	    override_tag, do_copy, *mem_entry_ptr);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	*vmaddr_ptr = 0;
	if (override_tag) {
		vm_flags = VM_MAKE_TAG(200);
	} else {
		vm_flags = 0;
	}
	kr = mach_vm_map(mach_task_self(),
	    vmaddr_ptr,
	    vmsize_orig,
	    0,              /* mask */
	    vm_flags | VM_FLAGS_ANYWHERE,
	    *mem_entry_ptr,
	    0,              /* offset */
	    FALSE,              /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "[override_tag:%d][do_copy:%d] mach_vm_map()",
	    override_tag, do_copy);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	*((unsigned char *)(uintptr_t)vmaddr_orig) = 'X';
	if (*(unsigned char *)(uintptr_t)*vmaddr_ptr == 'X') {
		T_QUIET;
		T_EXPECT_EQ(do_copy, 0, "[override_tag:%d][do_copy:%d] memory shared instead of copied",
		    override_tag, do_copy);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
	} else {
		T_QUIET;
		T_EXPECT_NE(do_copy, 0, "[override_tag:%d][do_copy:%d] memory copied instead of shared",
		    override_tag, do_copy);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
	}

	for (i = 0; i < vmsize_orig / vmsize_chunk; i++) {
		mach_vm_address_t       vmaddr_info;
		mach_vm_size_t          vmsize_info;

		vmaddr_info = *vmaddr_ptr + ((mach_vm_size_t)i * vmsize_chunk);
		vmsize_info = 0;
		depth = 1;
		ri_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
		kr = mach_vm_region_recurse(mach_task_self(),
		    &vmaddr_info,
		    &vmsize_info,
		    &depth,
		    (vm_region_recurse_info_t) &ri,
		    &ri_count);
		T_QUIET;
		T_EXPECT_MACH_SUCCESS(kr, "[override_tag:%d][do_copy:%d] mach_vm_region_recurse(0x%llx+0x%llx)",
		    override_tag, do_copy, *vmaddr_ptr, i * vmsize_chunk);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
		T_QUIET;
		T_EXPECT_EQ(vmaddr_info, *vmaddr_ptr + (i * vmsize_chunk), "[override_tag:%d][do_copy:%d] mach_vm_region_recurse(0x%llx+0x%llx) returned addr 0x%llx",
		    override_tag, do_copy, *vmaddr_ptr, (mach_vm_size_t)i * vmsize_chunk, vmaddr_info);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
		T_QUIET;
		T_EXPECT_EQ(vmsize_info, vmsize_chunk, "[override_tag:%d][do_copy:%d] mach_vm_region_recurse(0x%llx+0x%llx) returned size 0x%llx expected 0x%llx",
		    override_tag, do_copy, *vmaddr_ptr, (mach_vm_size_t)i * vmsize_chunk, vmsize_info, vmsize_chunk);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
		if (override_tag) {
			expected_tag = 200;
		} else {
			expected_tag = 100 + i;
		}
		T_QUIET;
		T_EXPECT_EQ(ri.user_tag, expected_tag, "[override_tag:%d][do_copy:%d] i=%u tag=%u expected %u",
		    override_tag, do_copy, i, ri.user_tag, expected_tag);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
	}

	if (++pass < 2) {
		do_copy = !do_copy;
		goto again;
	}

done:
	if (vmaddr_orig != 0) {
		mach_vm_deallocate(mach_task_self(),
		    vmaddr_orig,
		    vmsize_orig);
		vmaddr_orig = 0;
		vmsize_orig = 0;
	}
	if (vmaddr_copied != 0) {
		mach_vm_deallocate(mach_task_self(),
		    vmaddr_copied,
		    vmsize_copied);
		vmaddr_copied = 0;
		vmsize_copied = 0;
	}
	if (vmaddr_shared != 0) {
		mach_vm_deallocate(mach_task_self(),
		    vmaddr_shared,
		    vmsize_shared);
		vmaddr_shared = 0;
		vmsize_shared = 0;
	}
	if (mem_entry_copied != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), mem_entry_copied);
		mem_entry_copied = MACH_PORT_NULL;
	}
	if (mem_entry_shared != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), mem_entry_shared);
		mem_entry_shared = MACH_PORT_NULL;
	}

	return;
}

static void
test_map_memory_entry(void)
{
	kern_return_t           kr;
	mach_vm_address_t       vmaddr1, vmaddr2;
	mach_vm_size_t          vmsize1, vmsize2;
	mach_port_t             mem_entry;
	unsigned char           *cp1, *cp2;

	vmaddr1 = 0;
	vmsize1 = 0;
	vmaddr2 = 0;
	vmsize2 = 0;
	mem_entry = MACH_PORT_NULL;

	vmsize1 = 1;
	vmaddr1 = 0;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr1,
	    vmsize1,
	    VM_FLAGS_ANYWHERE);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "vm_allocate(%lld)", vmsize1);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	cp1 = (unsigned char *)(uintptr_t)vmaddr1;
	*cp1 = '1';

	vmsize2 = 1;
	mem_entry = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &vmsize2,
	    vmaddr1,                            /* offset */
	    (MAP_MEM_VM_COPY |
	    VM_PROT_READ | VM_PROT_WRITE),
	    &mem_entry,
	    MACH_PORT_NULL);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "mach_make_memory_entry()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}
	T_QUIET;
	T_EXPECT_GE(vmsize2, vmsize1, "vmsize2 (0x%llx) < vmsize1 (0x%llx)",
	    (uint64_t) vmsize2, (uint64_t) vmsize1);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}
	T_QUIET;
	T_EXPECT_NOTNULL(mem_entry, "mem_entry == 0x%x", mem_entry);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	vmaddr2 = 0;
	kr = mach_vm_map(mach_task_self(),
	    &vmaddr2,
	    vmsize2,
	    0,              /* mask */
	    VM_FLAGS_ANYWHERE,
	    mem_entry,
	    0,              /* offset */
	    TRUE,              /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_map()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	cp2 = (unsigned char *)(uintptr_t)vmaddr2;
	T_QUIET;
	T_EXPECT_TRUE(((*cp1 == '1') && (*cp2 == '1')), "*cp1/*cp2 0x%x/0x%x expected 0x%x/0x%x",
	    *cp1, *cp2, '1', '1');
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	*cp2 = '2';
	T_QUIET;
	T_EXPECT_TRUE(((*cp1 == '1') && (*cp2 == '2')), "*cp1/*cp2 0x%x/0x%x expected 0x%x/0x%x",
	    *cp1, *cp2, '1', '2');
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

done:
	if (vmaddr1 != 0) {
		mach_vm_deallocate(mach_task_self(), vmaddr1, vmsize1);
		vmaddr1 = 0;
		vmsize1 = 0;
	}
	if (vmaddr2 != 0) {
		mach_vm_deallocate(mach_task_self(), vmaddr2, vmsize2);
		vmaddr2 = 0;
		vmsize2 = 0;
	}
	if (mem_entry != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), mem_entry);
		mem_entry = MACH_PORT_NULL;
	}

	return;
}

T_DECL(memory_entry_tagging, "test mem entry tag for rdar://problem/23334087 \
    VM memory tags should be propagated through memory entries",
    T_META_ALL_VALID_ARCHS(true))
{
	test_memory_entry_tagging(0);
	test_memory_entry_tagging(1);
}

T_DECL(map_memory_entry, "test mapping mem entry for rdar://problem/22611816 \
    mach_make_memory_entry(MAP_MEM_VM_COPY) should never use a KERNEL_BUFFER \
    copy", T_META_ALL_VALID_ARCHS(true))
{
	test_map_memory_entry();
}

static char *vm_purgable_state[4] = { "NONVOLATILE", "VOLATILE", "EMPTY", "DENY" };

static uint64_t
task_footprint(void)
{
	task_vm_info_data_t ti;
	kern_return_t kr;
	mach_msg_type_number_t count;

	count = TASK_VM_INFO_COUNT;
	kr = task_info(mach_task_self(),
	    TASK_VM_INFO,
	    (task_info_t) &ti,
	    &count);
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(kr, "task_info()");
#if defined(__arm64__)
	T_QUIET;
	T_ASSERT_EQ(count, TASK_VM_INFO_COUNT, "task_info() count = %d (expected %d)",
	    count, TASK_VM_INFO_COUNT);
#endif /* defined(__arm64__) */
	return ti.phys_footprint;
}

T_DECL(purgeable_empty_to_volatile, "test task physical footprint when \
    emptying, volatilizing purgeable vm", T_META_TAG_VM_PREFERRED)
{
	kern_return_t kr;
	mach_vm_address_t vm_addr;
	mach_vm_size_t vm_size;
	char *cp;
	int ret;
	vm_purgable_t state;
	uint64_t footprint[8];

	vm_addr = 0;
	vm_size = 1 * 1024 * 1024;
	T_LOG("--> allocate %llu bytes", vm_size);
	kr = mach_vm_allocate(mach_task_self(),
	    &vm_addr,
	    vm_size,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	/* footprint0 */
	footprint[0] = task_footprint();
	T_LOG("    footprint[0] = %llu", footprint[0]);

	T_LOG("--> access %llu bytes", vm_size);
	for (cp = (char *) vm_addr;
	    cp < (char *) (vm_addr + vm_size);
	    cp += vm_kernel_page_size) {
		*cp = 'x';
	}
	/* footprint1 == footprint0 + vm_size */
	footprint[1] = task_footprint();
	T_LOG("    footprint[1] = %llu", footprint[1]);
	if (footprint[1] != footprint[0] + vm_size) {
		T_LOG("WARN: footprint[1] != footprint[0] + vm_size");
	}

	T_LOG("--> wire %llu bytes", vm_size / 2);
	ret = mlock((char *)vm_addr, (size_t) (vm_size / 2));
	T_ASSERT_POSIX_SUCCESS(ret, "mlock()");

	/* footprint2 == footprint1 */
	footprint[2] = task_footprint();
	T_LOG("    footprint[2] = %llu", footprint[2]);
	if (footprint[2] != footprint[1]) {
		T_LOG("WARN: footprint[2] != footprint[1]");
	}

	T_LOG("--> VOLATILE");
	state = VM_PURGABLE_VOLATILE;
	kr = mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state);
	T_ASSERT_MACH_SUCCESS(kr, "vm_purgable_control(VOLATILE)");
	T_ASSERT_EQ(state, VM_PURGABLE_NONVOLATILE, "NONVOLATILE->VOLATILE: state was %s",
	    vm_purgable_state[state]);
	/* footprint3 == footprint2 - (vm_size / 2) */
	footprint[3] = task_footprint();
	T_LOG("    footprint[3] = %llu", footprint[3]);
	if (footprint[3] != footprint[2] - (vm_size / 2)) {
		T_LOG("WARN: footprint[3] != footprint[2] - (vm_size / 2)");
	}

	T_LOG("--> EMPTY");
	state = VM_PURGABLE_EMPTY;
	kr = mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state);
	T_ASSERT_MACH_SUCCESS(kr, "vm_purgable_control(EMPTY)");
	if (state != VM_PURGABLE_VOLATILE &&
	    state != VM_PURGABLE_EMPTY) {
		T_ASSERT_FAIL("VOLATILE->EMPTY: state was %s",
		    vm_purgable_state[state]);
	}
	/* footprint4 == footprint3 */
	footprint[4] = task_footprint();
	T_LOG("    footprint[4] = %llu", footprint[4]);
	if (footprint[4] != footprint[3]) {
		T_LOG("WARN: footprint[4] != footprint[3]");
	}

	T_LOG("--> unwire %llu bytes", vm_size / 2);
	ret = munlock((char *)vm_addr, (size_t) (vm_size / 2));
	T_ASSERT_POSIX_SUCCESS(ret, "munlock()");

	/* footprint5 == footprint4 - (vm_size/2) (unless memory pressure) */
	/* footprint5 == footprint0 */
	footprint[5] = task_footprint();
	T_LOG("    footprint[5] = %llu", footprint[5]);
	if (footprint[5] != footprint[4] - (vm_size / 2)) {
		T_LOG("WARN: footprint[5] != footprint[4] - (vm_size/2)");
	}
	if (footprint[5] != footprint[0]) {
		T_LOG("WARN: footprint[5] != footprint[0]");
	}

	T_LOG("--> VOLATILE");
	state = VM_PURGABLE_VOLATILE;
	kr = mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state);
	T_ASSERT_MACH_SUCCESS(kr, "vm_purgable_control(VOLATILE)");
	T_ASSERT_EQ(state, VM_PURGABLE_EMPTY, "EMPTY->VOLATILE: state == %s",
	    vm_purgable_state[state]);
	/* footprint6 == footprint5 */
	/* footprint6 == footprint0 */
	footprint[6] = task_footprint();
	T_LOG("    footprint[6] = %llu", footprint[6]);
	if (footprint[6] != footprint[5]) {
		T_LOG("WARN: footprint[6] != footprint[5]");
	}
	if (footprint[6] != footprint[0]) {
		T_LOG("WARN: footprint[6] != footprint[0]");
	}

	T_LOG("--> NONVOLATILE");
	state = VM_PURGABLE_NONVOLATILE;
	kr = mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state);
	T_ASSERT_MACH_SUCCESS(kr, "vm_purgable_control(NONVOLATILE)");
	T_ASSERT_EQ(state, VM_PURGABLE_EMPTY, "EMPTY->NONVOLATILE: state == %s",
	    vm_purgable_state[state]);
	/* footprint7 == footprint6 */
	/* footprint7 == footprint0 */
	footprint[7] = task_footprint();
	T_LOG("    footprint[7] = %llu", footprint[7]);
	if (footprint[7] != footprint[6]) {
		T_LOG("WARN: footprint[7] != footprint[6]");
	}
	if (footprint[7] != footprint[0]) {
		T_LOG("WARN: footprint[7] != footprint[0]");
	}
}

static kern_return_t
get_reusable_size(uint64_t *reusable)
{
	task_vm_info_data_t     ti;
	mach_msg_type_number_t  ti_count = TASK_VM_INFO_COUNT;
	kern_return_t kr;

	kr = task_info(mach_task_self(),
	    TASK_VM_INFO,
	    (task_info_t) &ti,
	    &ti_count);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "task_info()");
	T_QUIET;
	*reusable = ti.reusable;
	return kr;
}

T_DECL(madvise_free_cow_pageout, "madvise(FREE) + cow + pageout",
    T_META_ASROOT(true),
    T_META_RUN_CONCURRENTLY(true),
    T_META_ALL_VALID_ARCHS(true))
{
	kern_return_t kr;
	mach_vm_address_t vm_addr, vm_addr2;
	mach_vm_size_t vm_size;
	vm_prot_t cur_prot, max_prot;
	int ret;
	char vec;
	int new_val;

	T_SETUPBEGIN;
	new_val = 0;
	ret = sysctlbyname("vm.madvise_free_debug", NULL, NULL, &new_val, sizeof(new_val));
	T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(vm.madvise_free_debug)");
	ret = sysctlbyname("vm.madvise_free_debug_sometimes", NULL, NULL, &new_val, sizeof(new_val));
	T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(vm.madvise_free_debug_sometimes)");
	T_SETUPEND;

	/*
	 * COPY_NONE
	 */
	T_LOG("COPY_NONE");
	vm_addr = 0;
	vm_size = 16 * 1024;
	kr = mach_vm_allocate(mach_task_self(), &vm_addr, vm_size, VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_allocate()");
	*(char *)vm_addr = 'x';
	ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_FREE);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_FREE)");
	T_EXPECT_EQ((int)*(unsigned char *)(uintptr_t)vm_addr, (int)'x', "contents before pageout");
	do {
		ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_PAGEOUT);
		T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_PAGEOUT)");
		usleep(10000);
		ret = mincore((char *)(uintptr_t)vm_addr, 1, &vec);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore()");
	} while (vec & MINCORE_INCORE);
	T_EXPECT_EQ((int)*(unsigned char *)(uintptr_t)vm_addr, 0, "COPY_NONE contents after pageout");
	*(char *)vm_addr = 'x';
	ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_FREE);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_FREE)");
	/* make a copy */
	vm_addr2 = 0;
	kr = mach_vm_remap(mach_task_self(), &vm_addr2, vm_size, 0, VM_FLAGS_ANYWHERE,
	    mach_task_self(), vm_addr, true, &cur_prot, &max_prot,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_remap()");
	T_EXPECT_EQ((int)*(unsigned char *)(uintptr_t)vm_addr2, (int)'x', "copied contents before pageout");
	do {
		ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_PAGEOUT);
		T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_PAGEOUT)");
		usleep(10000);
		ret = mincore((char *)(uintptr_t)vm_addr, 1, &vec);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore()");
	} while (vec & MINCORE_INCORE);
	T_EXPECT_EQ((int)*(unsigned char *)(uintptr_t)vm_addr2, (int)'x', "COPY_NONE copied contents after pageout");

	/*
	 * COPY_DELAY
	 */
	T_LOG("COPY_DELAY");
	vm_addr = 0;
	vm_size = 16 * 1024;
	kr = mach_vm_allocate(mach_task_self(), &vm_addr, vm_size, VM_FLAGS_ANYWHERE);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_allocate()");
	*(char *)vm_addr = 'x';
	ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_FREE);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_FREE)");
	T_EXPECT_EQ((int)*(unsigned char *)(uintptr_t)vm_addr, (int)'x', "contents before pageout");
	do {
		ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_PAGEOUT);
		T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_PAGEOUT)");
		usleep(10000);
		ret = mincore((char *)(uintptr_t)vm_addr, 1, &vec);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore()");
	} while (vec & MINCORE_INCORE);
	T_EXPECT_EQ((int)*(unsigned char *)(uintptr_t)vm_addr, 0, "COPY_DELAY contents after pageout");
	*(char *)vm_addr = 'x';
	ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_FREE);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_FREE)");
	vm_addr2 = 0;
	kr = mach_vm_remap(mach_task_self(), &vm_addr2, vm_size, 0, VM_FLAGS_ANYWHERE,
	    mach_task_self(), vm_addr, false, &cur_prot, &max_prot,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_remap(copy=false)");
	ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_FREE);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_FREE)");
	/* make a copy */
	vm_addr2 = 0;
	kr = mach_vm_remap(mach_task_self(), &vm_addr2, vm_size, 0, VM_FLAGS_ANYWHERE,
	    mach_task_self(), vm_addr, true, &cur_prot, &max_prot,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_remap(copy=true)");
	T_EXPECT_EQ((int)*(unsigned char *)(uintptr_t)vm_addr2, (int)'x', "copied contents before pageout");
	do {
		ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_PAGEOUT);
		T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_PAGEOUT)");
		usleep(10000);
		ret = mincore((char *)(uintptr_t)vm_addr, 1, &vec);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore()");
	} while (vec & MINCORE_INCORE);
	T_EXPECT_EQ((int)*(unsigned char *)(uintptr_t)vm_addr2, (int)'x', "COPY_DELAY copied contents after pageout");

	/*
	 * COPY_SYMMETRIC
	 */
	T_LOG("COPY_SYMMETRIC");
	vm_addr = 0;
	vm_size = 16 * 1024;
	kr = mach_vm_allocate(mach_task_self(), &vm_addr, vm_size, VM_FLAGS_ANYWHERE);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_allocate()");
	*(char *)vm_addr = 'x';
	ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_FREE);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_FREE)");
	ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_FREE);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_FREE)");
	T_EXPECT_EQ((int)*(unsigned char *)(uintptr_t)vm_addr, (int)'x', "contents before pageout");
	do {
		ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_PAGEOUT);
		T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_PAGEOUT)");
		usleep(10000);
		ret = mincore((char *)(uintptr_t)vm_addr, 1, &vec);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore()");
	} while (vec & MINCORE_INCORE);
	T_EXPECT_EQ((int)*(unsigned char *)(uintptr_t)vm_addr, 0, "COPY_SYMMETRIC contents after pageout");
	*(char *)vm_addr = 'x';
	ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_FREE);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_FREE)");
	/* make a copy */
	vm_addr2 = 0;
	kr = mach_vm_remap(mach_task_self(), &vm_addr2, vm_size, 0, VM_FLAGS_ANYWHERE,
	    mach_task_self(), vm_addr, true, &cur_prot, &max_prot,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_remap()");
	T_EXPECT_EQ((int)*(unsigned char *)(uintptr_t)vm_addr2, (int)'x', "copied contents before pageout");
	do {
		ret = madvise((char *)(uintptr_t)vm_addr, vm_size, MADV_PAGEOUT);
		T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_PAGEOUT)");
		usleep(10000);
		ret = mincore((char *)(uintptr_t)vm_addr, 1, &vec);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore()");
	} while (vec & MINCORE_INCORE);
	T_EXPECT_EQ((int)*(unsigned char *)(uintptr_t)vm_addr2, (int)'x', "COPY_SYMMETRIC copied contents after pageout");
}

T_DECL(madvise_shared, "test madvise shared for rdar://problem/2295713 logging \
    rethink needs madvise(MADV_FREE_HARDER)",
    T_META_RUN_CONCURRENTLY(false),
    T_META_ALL_VALID_ARCHS(true))
{
	vm_address_t            vmaddr = 0, vmaddr2 = 0;
	vm_size_t               vmsize, vmsize1, vmsize2;
	kern_return_t           kr;
	char                    *cp;
	vm_prot_t               curprot, maxprot;
	int                     ret;
	int                     vmflags;
	uint64_t                footprint_before, footprint_after;
	uint64_t                reusable_before, reusable_after, reusable_expected;


	vmsize1 = 64 * 1024; /* 64KB to madvise() */
	vmsize2 = 32 * 1024; /* 32KB to mlock() */
	vmsize = vmsize1 + vmsize2;
	vmflags = VM_FLAGS_ANYWHERE;
	VM_SET_FLAGS_ALIAS(vmflags, VM_MEMORY_MALLOC);

	kr = get_reusable_size(&reusable_before);
	if (kr) {
		goto done;
	}

	kr = vm_allocate(mach_task_self(),
	    &vmaddr,
	    vmsize,
	    vmflags);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "vm_allocate()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	for (cp = (char *)(uintptr_t)vmaddr;
	    cp < (char *)(uintptr_t)(vmaddr + vmsize);
	    cp++) {
		*cp = 'x';
	}

	kr = vm_remap(mach_task_self(),
	    &vmaddr2,
	    vmsize,
	    0,           /* mask */
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    vmaddr,
	    FALSE,           /* copy */
	    &curprot,
	    &maxprot,
	    VM_INHERIT_DEFAULT);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "vm_remap()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	for (cp = (char *)(uintptr_t)vmaddr2;
	    cp < (char *)(uintptr_t)(vmaddr2 + vmsize);
	    cp++) {
		T_QUIET;
		T_EXPECT_EQ(*cp, 'x', "vmaddr=%p vmaddr2=%p %p:0x%x",
		    (void *)(uintptr_t)vmaddr,
		    (void *)(uintptr_t)vmaddr2,
		    (void *)cp,
		    (unsigned char)*cp);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
	}
	cp = (char *)(uintptr_t)vmaddr;
	*cp = 'X';
	cp = (char *)(uintptr_t)vmaddr2;
	T_QUIET;
	T_EXPECT_EQ(*cp, 'X', "memory was not properly shared");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

#if defined(__x86_64__) || defined(__i386__)
	if (COMM_PAGE_READ(uint64_t, CPU_CAPABILITIES64) & kIsTranslated) {
		T_LOG("Skipping madvise reusable tests because we're running under translation.");
		goto done;
	}
#endif /* defined(__x86_64__) || defined(__i386__) */

	ret = mlock((char *)(uintptr_t)(vmaddr2 + vmsize1),
	    vmsize2);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "mlock()");

	footprint_before = task_footprint();

	ret = madvise((char *)(uintptr_t)vmaddr,
	    vmsize1,
	    MADV_FREE_REUSABLE);
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(ret, "madvise()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	footprint_after = task_footprint();
	T_ASSERT_EQ(footprint_after, footprint_before - 2 * vmsize1, NULL);

	kr = get_reusable_size(&reusable_after);
	if (kr) {
		goto done;
	}
	reusable_expected = 2ULL * vmsize1 + reusable_before;
	T_EXPECT_EQ(reusable_after, reusable_expected, "actual=%lld expected %lld",
	    reusable_after, reusable_expected);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

done:
	if (vmaddr != 0) {
		vm_deallocate(mach_task_self(), vmaddr, vmsize);
		vmaddr = 0;
	}
	if (vmaddr2 != 0) {
		vm_deallocate(mach_task_self(), vmaddr2, vmsize);
		vmaddr2 = 0;
	}
}

T_DECL(madvise_purgeable_can_reuse, "test madvise purgeable can reuse for \
    rdar://problem/37476183 Preview Footprint memory regressions ~100MB \
    [ purgeable_malloc became eligible for reuse ]",
    T_META_ALL_VALID_ARCHS(true))
{
#if defined(__x86_64__) || defined(__i386__)
	if (COMM_PAGE_READ(uint64_t, CPU_CAPABILITIES64) & kIsTranslated) {
		T_SKIP("madvise reusable is not supported under Rosetta translation. Skipping.)");
	}
#endif /* defined(__x86_64__) || defined(__i386__) */
	vm_address_t            vmaddr = 0;
	vm_size_t               vmsize;
	kern_return_t           kr;
	char                    *cp;
	int                     ret;

	vmsize = 10 * 1024 * 1024; /* 10MB */
	kr = vm_allocate(mach_task_self(),
	    &vmaddr,
	    vmsize,
	    (VM_FLAGS_ANYWHERE |
	    VM_FLAGS_PURGABLE |
	    VM_MAKE_TAG(VM_MEMORY_MALLOC)));
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "vm_allocate()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	for (cp = (char *)(uintptr_t)vmaddr;
	    cp < (char *)(uintptr_t)(vmaddr + vmsize);
	    cp++) {
		*cp = 'x';
	}

	ret = madvise((char *)(uintptr_t)vmaddr,
	    vmsize,
	    MADV_CAN_REUSE);
	T_QUIET;
	T_EXPECT_TRUE(((ret == -1) && (errno == EINVAL)), "madvise(): purgeable vm can't be adviced to reuse");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

done:
	if (vmaddr != 0) {
		vm_deallocate(mach_task_self(), vmaddr, vmsize);
		vmaddr = 0;
	}
}

static bool
validate_memory_is_zero(
	vm_address_t            start,
	vm_size_t               vmsize,
	vm_address_t           *non_zero_addr)
{
	for (vm_size_t sz = 0; sz < vmsize; sz += sizeof(uint64_t)) {
		vm_address_t addr = start + sz;

		if (*(uint64_t *)(addr) != 0) {
			*non_zero_addr = addr;
			return false;
		}
	}
	return true;
}

T_DECL(madvise_zero, "test madvise zero", T_META_TAG_VM_PREFERRED)
{
	vm_address_t            vmaddr = 0;
	vm_size_t               vmsize = PAGE_SIZE * 3;
	vm_address_t            non_zero_addr = 0;
	kern_return_t           kr;
	int                     ret;
	unsigned char           vec;

	kr = vm_allocate(mach_task_self(),
	    &vmaddr,
	    vmsize,
	    (VM_FLAGS_ANYWHERE |
	    VM_MAKE_TAG(VM_MEMORY_MALLOC)));
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "vm_allocate()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	memset((void *)vmaddr, 'A', vmsize);
	ret = madvise((void*)vmaddr, vmsize, MADV_FREE_REUSABLE);
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_FREE_REUSABLE)");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	memset((void *)vmaddr, 'B', PAGE_SIZE);
	ret = madvise((void*)vmaddr, vmsize, MADV_ZERO);
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_ZERO)");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	T_QUIET;
	T_EXPECT_EQ(validate_memory_is_zero(vmaddr, vmsize, &non_zero_addr), true,
	    "madvise(%p, %lu, MADV_ZERO) returned non zero mem at %p",
	    (void *)vmaddr, vmsize, (void *)non_zero_addr);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	memset((void *)vmaddr, 'C', PAGE_SIZE);
	ret = madvise((void*)vmaddr, vmsize, MADV_PAGEOUT);
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_PAGEOUT)");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	/* wait for the pages to be (asynchronously) compressed */
	T_QUIET; T_LOG("waiting for first page to be paged out");
	do {
		ret = mincore((void*)vmaddr, 1, (char *)&vec);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore(1st)");
	} while (vec & MINCORE_INCORE);
	T_QUIET; T_LOG("waiting for last page to be paged out");
	do {
		ret = mincore((void*)(vmaddr + vmsize - 1), 1, (char *)&vec);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mincore(last)");
	} while (vec & MINCORE_INCORE);

	ret = madvise((void*)vmaddr, vmsize, MADV_ZERO);
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(ret, "madvise(MADV_ZERO)");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}
	T_QUIET;
	T_EXPECT_EQ(validate_memory_is_zero(vmaddr, vmsize, &non_zero_addr), true,
	    "madvise(%p, %lu, MADV_ZERO) returned non zero mem at %p",
	    (void *)vmaddr, vmsize, (void *)non_zero_addr);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

done:
	if (vmaddr != 0) {
		vm_deallocate(mach_task_self(), vmaddr, vmsize);
		vmaddr = 0;
	}
}

T_DECL(madvise_zero_wired, "test madvise(MADV_ZERO_WIRED_PAGES)", T_META_TAG_VM_PREFERRED)
{
	vm_address_t            vmaddr;
	vm_address_t            vmaddr_remap;
	vm_size_t               vmsize = PAGE_SIZE * 3;
	vm_prot_t               cur_prot, max_prot;
	vm_address_t            non_zero_addr = 0;
	kern_return_t           kr;
	int                     ret;

	/*
	 * madvise(MADV_ZERO_WIRED_PAGES) should cause wired pages to get zero-filled
	 * when they get deallocated.
	 */
	vmaddr = 0;
	kr = vm_allocate(mach_task_self(),
	    &vmaddr,
	    vmsize,
	    (VM_FLAGS_ANYWHERE |
	    VM_MAKE_TAG(VM_MEMORY_MALLOC)));
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");
	memset((void *)vmaddr, 'A', vmsize);
	T_QUIET; T_ASSERT_EQ(*(char *)vmaddr, 'A', " ");
	vmaddr_remap = 0;
	kr = vm_remap(mach_task_self(), &vmaddr_remap, vmsize, 0, VM_FLAGS_ANYWHERE,
	    mach_task_self(), vmaddr, FALSE, &cur_prot, &max_prot,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_remap()");
	ret = madvise((void*)vmaddr, vmsize, MADV_ZERO_WIRED_PAGES);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "madvise(MADV_ZERO_WIRED_PAGES)");
	ret = mlock((void*)vmaddr, vmsize);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mlock()");
	T_QUIET; T_ASSERT_EQ(*(char *)vmaddr, 'A', " ");
	ret = munmap((void*)vmaddr, vmsize);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "munmap()");
	T_ASSERT_EQ(*(char *)vmaddr_remap, 0, "wired pages are zero-filled on unmap");
	T_QUIET; T_ASSERT_EQ(validate_memory_is_zero(vmaddr_remap, vmsize, &non_zero_addr),
	    true, "madvise(%p, %lu, MADV_ZERO_WIRED) did not zero-fill mem at %p",
	    (void *)vmaddr, vmsize, (void *)non_zero_addr);
	ret = munmap((void *)vmaddr_remap, vmsize);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "munmap()");

	/*
	 * madvise(MADV_ZERO_WIRED_PAGES) should fail with EPERM if the
	 * mapping is not writable.
	 */
	vmaddr = 0;
	kr = vm_allocate(mach_task_self(),
	    &vmaddr,
	    vmsize,
	    (VM_FLAGS_ANYWHERE |
	    VM_MAKE_TAG(VM_MEMORY_MALLOC)));
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");
	memset((void *)vmaddr, 'A', vmsize);
	T_QUIET; T_ASSERT_EQ(*(char *)vmaddr, 'A', " ");
	ret = mprotect((void*)vmaddr, vmsize, PROT_READ);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mprotect(PROT_READ)");
	ret = madvise((void*)vmaddr, vmsize, MADV_ZERO_WIRED_PAGES);
	//T_LOG("madv() ret %d errno %d\n", ret, errno);
	T_ASSERT_POSIX_FAILURE(ret, EPERM,
	    "madvise(MADV_ZERO_WIRED_PAGES) returns EPERM on non-writable mapping ret %d errno %d", ret, errno);
	ret = munmap((void*)vmaddr, vmsize);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "munmap()");

	/*
	 * madvise(MADV_ZERO_WIRED_PAGES) should not zero-fill the pages
	 * if the mapping is no longer writable when it gets unwired.
	 */
	vmaddr = 0;
	kr = vm_allocate(mach_task_self(),
	    &vmaddr,
	    vmsize,
	    (VM_FLAGS_ANYWHERE |
	    VM_MAKE_TAG(VM_MEMORY_MALLOC)));
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");
	memset((void *)vmaddr, 'A', vmsize);
	T_QUIET; T_ASSERT_EQ(*(char *)vmaddr, 'A', " ");
	vmaddr_remap = 0;
	kr = vm_remap(mach_task_self(), &vmaddr_remap, vmsize, 0, VM_FLAGS_ANYWHERE,
	    mach_task_self(), vmaddr, FALSE, &cur_prot, &max_prot,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_remap()");
	ret = madvise((void*)vmaddr, vmsize, MADV_ZERO_WIRED_PAGES);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "madvise(MADV_ZERO_WIRED_PAGES)");
	ret = mprotect((void*)vmaddr, vmsize, PROT_READ);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mprotect(PROT_READ)");
	ret = mlock((void*)vmaddr, vmsize);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mlock()");
	T_QUIET; T_ASSERT_EQ(*(char *)vmaddr, 'A', " ");
	ret = munmap((void*)vmaddr, vmsize);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "munmap()");
	T_ASSERT_EQ(*(char *)vmaddr_remap, 'A', "RO wired pages NOT zero-filled on unmap");
	ret = munmap((void *)vmaddr_remap, vmsize);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "munmap()");
}

#define DEST_PATTERN 0xFEDCBA98

T_DECL(map_read_overwrite, "test overwriting vm map from other map - \
    rdar://31075370",
    T_META_ALL_VALID_ARCHS(true))
{
	kern_return_t           kr;
	mach_vm_address_t       vmaddr1, vmaddr2;
	mach_vm_size_t          vmsize1, vmsize2;
	uint32_t                *ip;
	uint32_t                i;

	vmaddr1 = 0;
	vmsize1 = 4 * 4096;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr1,
	    vmsize1,
	    VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	ip = (uint32_t *)(uintptr_t)vmaddr1;
	for (i = 0; (mach_vm_size_t)i < vmsize1 / sizeof(*ip); i++) {
		ip[i] = i;
	}

	vmaddr2 = 0;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr2,
	    vmsize1,
	    VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	ip = (uint32_t *)(uintptr_t)vmaddr2;
	for (i = 0; (mach_vm_size_t)i < vmsize1 / sizeof(*ip); i++) {
		ip[i] = DEST_PATTERN;
	}

	vmsize2 = vmsize1 - 2 * (sizeof(*ip));
	kr = mach_vm_read_overwrite(mach_task_self(),
	    vmaddr1 + sizeof(*ip),
	    vmsize2,
	    vmaddr2 + sizeof(*ip),
	    &vmsize2);
	T_ASSERT_MACH_SUCCESS(kr, "vm_read_overwrite()");

	ip = (uint32_t *)(uintptr_t)vmaddr2;
	for (i = 0; i < 1; i++) {
		T_QUIET;
		T_ASSERT_EQ(ip[i], DEST_PATTERN, "vmaddr2[%d] = 0x%x instead of 0x%x",
		    i, ip[i], DEST_PATTERN);
	}
	for (; (mach_vm_size_t)i < (vmsize1 - 2) / sizeof(*ip); i++) {
		T_QUIET;
		T_ASSERT_EQ(ip[i], i, "vmaddr2[%d] = 0x%x instead of 0x%x",
		    i, ip[i], i);
	}
	for (; (mach_vm_size_t)i < vmsize1 / sizeof(*ip); i++) {
		T_QUIET;
		T_ASSERT_EQ(ip[i], DEST_PATTERN, "vmaddr2[%d] = 0x%x instead of 0x%x",
		    i, ip[i], DEST_PATTERN);
	}
}

T_DECL(copy_none_use_pmap, "test copy-on-write remapping of COPY_NONE vm \
    objects - rdar://35610377",
    T_META_ALL_VALID_ARCHS(true))
{
	kern_return_t           kr;
	mach_vm_address_t       vmaddr1, vmaddr2, vmaddr3;
	mach_vm_size_t          vmsize;
	vm_prot_t               curprot, maxprot;

	vmsize = 32 * 1024 * 1024;

	vmaddr1 = 0;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr1,
	    vmsize,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	memset((void *)(uintptr_t)vmaddr1, 'x', vmsize);

	vmaddr2 = 0;
	kr = mach_vm_remap(mach_task_self(),
	    &vmaddr2,
	    vmsize,
	    0,                /* mask */
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    vmaddr1,
	    TRUE,                /* copy */
	    &curprot,
	    &maxprot,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "vm_remap() #1");

	vmaddr3 = 0;
	kr = mach_vm_remap(mach_task_self(),
	    &vmaddr3,
	    vmsize,
	    0,                /* mask */
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    vmaddr2,
	    TRUE,                /* copy */
	    &curprot,
	    &maxprot,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "vm_remap() #2");
}

T_DECL(purgable_deny, "test purgeable memory is not allowed to be converted to \
    non-purgeable - rdar://31990033",
    T_META_ALL_VALID_ARCHS(true))
{
	kern_return_t   kr;
	vm_address_t    vmaddr;
	vm_purgable_t   state;

	vmaddr = 0;
	kr = vm_allocate(mach_task_self(), &vmaddr, 1,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	state = VM_PURGABLE_DENY;
	kr = vm_purgable_control(mach_task_self(), vmaddr,
	    VM_PURGABLE_SET_STATE, &state);
	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT,
	    "vm_purgable_control(VM_PURGABLE_DENY) -> 0x%x (%s)",
	    kr, mach_error_string(kr));

	kr = vm_deallocate(mach_task_self(), vmaddr, 1);
	T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate()");
}

#define VMSIZE 0x10000

T_DECL(vm_remap_zero, "test vm map of zero size - rdar://33114981",
    T_META_ALL_VALID_ARCHS(true))
{
	kern_return_t           kr;
	mach_vm_address_t       vmaddr1, vmaddr2;
	mach_vm_size_t          vmsize;
	vm_prot_t               curprot, maxprot;

	vmaddr1 = 0;
	vmsize = VMSIZE;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr1,
	    vmsize,
	    VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	vmaddr2 = 0;
	vmsize = 0;
	kr = mach_vm_remap(mach_task_self(),
	    &vmaddr2,
	    vmsize,
	    0,
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    vmaddr1,
	    FALSE,
	    &curprot,
	    &maxprot,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT, "vm_remap(size=0x%llx) 0x%x (%s)",
	    vmsize, kr, mach_error_string(kr));

	vmaddr2 = 0;
	vmsize = (mach_vm_size_t)-2;
	kr = mach_vm_remap(mach_task_self(),
	    &vmaddr2,
	    vmsize,
	    0,
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    vmaddr1,
	    FALSE,
	    &curprot,
	    &maxprot,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT, "vm_remap(size=0x%llx) 0x%x (%s)",
	    vmsize, kr, mach_error_string(kr));
}

extern int __shared_region_check_np(uint64_t *);

T_DECL(nested_pmap_trigger, "nested pmap should only be triggered from kernel \
    - rdar://problem/41481703",
    T_META_ALL_VALID_ARCHS(true))
{
	int                     ret;
	kern_return_t           kr;
	mach_vm_address_t       sr_start;
	mach_vm_size_t          vmsize;
	mach_vm_address_t       vmaddr;
	mach_port_t             mem_entry;

	ret = __shared_region_check_np(&sr_start);
	if (ret != 0) {
		int saved_errno;
		saved_errno = errno;

		T_ASSERT_EQ(saved_errno, ENOMEM, "__shared_region_check_np() %d (%s)",
		    saved_errno, strerror(saved_errno));
		T_END;
	}

	vmsize = PAGE_SIZE;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &vmsize,
	    sr_start,
	    MAP_MEM_VM_SHARE | VM_PROT_READ,
	    &mem_entry,
	    MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "make_memory_entry(0x%llx)", sr_start);

	vmaddr = 0;
	kr = mach_vm_map(mach_task_self(),
	    &vmaddr,
	    vmsize,
	    0,
	    VM_FLAGS_ANYWHERE,
	    mem_entry,
	    0,
	    FALSE,
	    VM_PROT_READ,
	    VM_PROT_READ,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "vm_map()");
}

static const char *prot_str[] = { "---", "r--", "-w-", "rw-", "--x", "r-x", "-wx", "rwx" };
static const char *share_mode_str[] = { "---", "COW", "PRIVATE", "EMPTY", "SHARED", "TRUESHARED", "PRIVATE_ALIASED", "SHARED_ALIASED", "LARGE_PAGE" };

T_DECL(shared_region_share_writable, "sharing a writable mapping of the shared region shoudl not give write access to shared region - rdar://problem/74469953",
    T_META_ALL_VALID_ARCHS(true))
{
	int ret;
	uint64_t sr_start;
	kern_return_t kr;
	mach_vm_address_t address, tmp_address, remap_address;
	mach_vm_size_t size, tmp_size, remap_size;
	uint32_t depth;
	mach_msg_type_number_t count;
	vm_region_submap_info_data_64_t info;
	vm_prot_t cur_prot, max_prot;
	uint32_t before, after, remap;
	mach_port_t mem_entry;

	ret = __shared_region_check_np(&sr_start);
	if (ret != 0) {
		int saved_errno;
		saved_errno = errno;

		T_ASSERT_EQ(saved_errno, ENOMEM, "__shared_region_check_np() %d (%s)",
		    saved_errno, strerror(saved_errno));
		T_END;
	}
	T_LOG("SHARED_REGION_BASE 0x%llx", SHARED_REGION_BASE);
	T_LOG("SHARED_REGION_SIZE 0x%llx", SHARED_REGION_SIZE);
	T_LOG("shared region starts at 0x%llx", sr_start);
	T_QUIET; T_ASSERT_GE(sr_start, SHARED_REGION_BASE,
	    "shared region starts below BASE");
	T_QUIET; T_ASSERT_LT(sr_start, SHARED_REGION_BASE + SHARED_REGION_SIZE,
	    "shared region starts above BASE+SIZE");

	/*
	 * Step 1 - check that one can not get write access to a read-only
	 * mapping in the shared region.
	 */
	size = 0;
	for (address = SHARED_REGION_BASE;
	    address < SHARED_REGION_BASE + SHARED_REGION_SIZE;
	    address += size) {
		size = 0;
		depth = 99;
		count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kr = mach_vm_region_recurse(mach_task_self(),
		    &address,
		    &size,
		    &depth,
		    (vm_region_recurse_info_t)&info,
		    &count);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_region_recurse()");
		if (kr == KERN_INVALID_ADDRESS) {
			T_SKIP("could not find read-only nested mapping");
			T_END;
		}
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
		T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
		    address, address + size, depth,
		    prot_str[info.protection],
		    prot_str[info.max_protection],
		    share_mode_str[info.share_mode],
		    info.object_id);
		if (depth > 0 &&
		    (info.protection == VM_PROT_READ) &&
		    (info.max_protection == VM_PROT_READ)) {
			/* nested and read-only: bingo! */
			break;
		}
	}
	T_LOG("Found address 0x%llx", address);

	if (address >= SHARED_REGION_BASE + SHARED_REGION_SIZE) {
		T_SKIP("could not find read-only nested mapping");
		T_END;
	}

	/* test vm_remap() of RO */
	before = *(uint32_t *)(uintptr_t)address;
	remap_address = 0;
	remap_size = size;
	kr = mach_vm_remap(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
	    mach_task_self(),
	    address,
	    FALSE,
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_remap()");
//	T_QUIET; T_ASSERT_EQ(cur_prot, VM_PROT_READ, "cur_prot is read-only");
//	T_QUIET; T_ASSERT_EQ(max_prot, VM_PROT_READ, "max_prot is read-only");
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "cur_prot still read-only");
//	T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "max_prot still read-only");
	/* check that new mapping is read-only */
	tmp_address = remap_address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, remap_address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "new cur_prot read-only");
//	T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "new max_prot read-only");
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
	// this would crash if actually read-only, do it safely with try_write_byte()
	// *(uint32_t *)(uintptr_t)remap_address = before + 1;
	// RANGELOCKINGTODO: make this check not fail rdar://150779766
	//bool write_succeded = try_write_byte(remap_address, (uint8_t)(before + 1), &kr);
	//T_QUIET; T_ASSERT_FALSE(write_succeded, "fail to write to read-only address");

	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("vm_remap(): 0x%llx 0x%x -> 0x%x", address, before, after);
//	*(uint32_t *)(uintptr_t)remap_address = before;
	if (before != after) {
		T_FAIL("vm_remap() bypassed copy-on-write");
	} else {
		T_PASS("vm_remap() did not bypass copy-on-write");
	}
	/* cleanup */
	kr = mach_vm_deallocate(mach_task_self(), remap_address, remap_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_deallocate()");
	T_PASS("vm_remap() read-only");

#if defined(VM_MEMORY_ROSETTA)
	if (dlsym(RTLD_DEFAULT, "mach_vm_remap_new") == NULL) {
		T_PASS("vm_remap_new() is not present");
		goto skip_vm_remap_new_ro;
	}
	/* test vm_remap_new() of RO */
	before = *(uint32_t *)(uintptr_t)address;
	remap_address = 0;
	remap_size = size;
	cur_prot = VM_PROT_READ | VM_PROT_WRITE;
	max_prot = VM_PROT_READ | VM_PROT_WRITE;
	kr = mach_vm_remap_new(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    address,
	    /*copy=*/ FALSE,
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	// we're asking for share by the shared-cache submap entry has needs_copy=true so it's going to be a COW remap
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_remap_new()");
	if (kr == KERN_PROTECTION_FAILURE) {
		/* wrong but not a security issue... */
		goto skip_vm_remap_new_ro;
	}
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_remap_new()");
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
	// This mapping is RW now so we can write to it
	*(uint32_t *)(uintptr_t)remap_address = before + 1;
	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("vm_remap_new(): 0x%llx 0x%x -> 0x%x", address, before, after);
	*(uint32_t *)(uintptr_t)remap_address = before;
	if (before != after) {
		T_FAIL("vm_remap_new() bypassed copy-on-write");
	} else {
		T_PASS("vm_remap_new() did not bypass copy-on-write");
	}
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "cur_prot still read-only");
	T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "max_prot still read-only");
	T_PASS("vm_remap_new() read-only");
skip_vm_remap_new_ro:
#else /* defined(VM_MEMORY_ROSETTA) */
	/* pre-BigSur SDK: no vm_remap_new() */
	T_LOG("No vm_remap_new() to test");
#endif /* defined(VM_MEMORY_ROSETTA) */

	/* test mach_make_memory_entry_64(VM_SHARE) of RO */
	before = *(uint32_t *)(uintptr_t)address;
	remap_size = size;
	mem_entry = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &remap_size,
	    address,
	    MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE,
	    &mem_entry,
	    MACH_PORT_NULL);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_make_memory_entry_64(VM_SHARE)");
	if (kr == KERN_PROTECTION_FAILURE) {
		/* wrong but not a security issue... */
		goto skip_mem_entry_vm_share_ro;
	}
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry_64(VM_SHARE)");
	remap_address = 0;
	kr = mach_vm_map(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,              /* mask */
	    VM_FLAGS_ANYWHERE,
	    mem_entry,
	    0,              /* offset */
	    FALSE,              /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_map()");
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
	*(uint32_t *)(uintptr_t)remap_address = before + 1;
	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("mem_entry(VM_SHARE): 0x%llx 0x%x -> 0x%x", address, before, after);
	*(uint32_t *)(uintptr_t)remap_address = before;
	if (before != after) {
		T_FAIL("mem_entry(VM_SHARE) bypassed copy-on-write");
	} else {
		T_PASS("mem_entry(VM_SHARE) did not bypass copy-on-write");
	}
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "cur_prot still read-only");
	T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "max_prot still read-only");
	/* check that new mapping is a copy */
	tmp_address = remap_address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, remap_address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_EQ(depth, 0, "new mapping is unnested");
//	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "new cur_prot read-only");
//	T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "new max_prot read-only");
	/* cleanup */
	kr = mach_vm_deallocate(mach_task_self(), remap_address, remap_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_deallocate()");
	T_PASS("mem_entry(VM_SHARE) read-only");
skip_mem_entry_vm_share_ro:

	/* test mach_make_memory_entry_64() of RO */
	before = *(uint32_t *)(uintptr_t)address;
	remap_size = size;
	mem_entry = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &remap_size,
	    address,
	    VM_PROT_READ | VM_PROT_WRITE,
	    &mem_entry,
	    MACH_PORT_NULL);
	T_QUIET; T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "mach_make_memory_entry_64()");
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
//	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "cur_prot still read-only");
	if (depth > 0) {
		T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "max_prot still read-only");
	}
	T_PASS("mem_entry() read-only");

	/* test mach_make_memory_entry_64(READ | WRITE | VM_PROT_IS_MASK) of RO */
	before = *(uint32_t *)(uintptr_t)address;
	remap_size = size;
	mem_entry = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &remap_size,
	    address,
	    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_IS_MASK,
	    &mem_entry,
	    MACH_PORT_NULL);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry_64(READ | WRITE | IS_MASK)");
	remap_address = 0;
	kr = mach_vm_map(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,              /* mask */
	    VM_FLAGS_ANYWHERE,
	    mem_entry,
	    0,              /* offset */
	    FALSE,              /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_RIGHT, "vm_map(read/write)");
	remap_address = 0;
	kr = mach_vm_map(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,              /* mask */
	    VM_FLAGS_ANYWHERE,
	    mem_entry,
	    0,              /* offset */
	    FALSE,              /* copy */
	    VM_PROT_READ,
	    VM_PROT_READ,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_map(read only)");
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
//	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "cur_prot still read-only");
	if (depth > 0) {
		T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "max_prot still read-only");
	}
	/* check that new mapping is a copy */
	tmp_address = remap_address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, remap_address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_EQ(depth, 0, "new mapping is unnested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "new cur_prot read-only");
	T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "new max_prot read-only");
	/* cleanup */
	kr = mach_vm_deallocate(mach_task_self(), remap_address, remap_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_deallocate()");
	T_PASS("mem_entry(READ | WRITE | IS_MASK) read-only");


	/*
	 * Step 2 - check that one can not share write access with a writable
	 * mapping in the shared region.
	 */
	size = 0;
	for (address = SHARED_REGION_BASE;
	    address < SHARED_REGION_BASE + SHARED_REGION_SIZE;
	    address += size) {
		size = 0;
		depth = 99;
		count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kr = mach_vm_region_recurse(mach_task_self(),
		    &address,
		    &size,
		    &depth,
		    (vm_region_recurse_info_t)&info,
		    &count);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_region_recurse()");
		if (kr == KERN_INVALID_ADDRESS) {
			T_SKIP("could not find writable nested mapping");
			T_END;
		}
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
		T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
		    address, address + size, depth,
		    prot_str[info.protection],
		    prot_str[info.max_protection],
		    share_mode_str[info.share_mode],
		    info.object_id);
		if (depth > 0 && (info.protection & VM_PROT_WRITE)) {
			/* nested and writable: bingo! */
			break;
		}
	}
	if (address >= SHARED_REGION_BASE + SHARED_REGION_SIZE) {
		T_SKIP("could not find writable nested mapping");
		T_END;
	}

	/* test vm_remap() of RW */
	before = *(uint32_t *)(uintptr_t)address;
	remap_address = 0;
	remap_size = size;
	kr = mach_vm_remap(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
	    mach_task_self(),
	    address,
	    FALSE,
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_remap()");
	if (!(cur_prot & VM_PROT_WRITE)) {
		T_LOG("vm_remap(): 0x%llx not writable %s/%s",
		    remap_address, prot_str[cur_prot], prot_str[max_prot]);
		T_ASSERT_FAIL("vm_remap() remapping not writable");
	}
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
	*(uint32_t *)(uintptr_t)remap_address = before + 1;
	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("vm_remap(): 0x%llx 0x%x -> 0x%x", address, before, after);
	*(uint32_t *)(uintptr_t)remap_address = before;
	if (before != after) {
		T_FAIL("vm_remap() bypassed copy-on-write");
	} else {
		T_PASS("vm_remap() did not bypass copy-on-write");
	}
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_DEFAULT, "cur_prot still writable");
	T_QUIET; T_ASSERT_EQ((info.max_protection & VM_PROT_WRITE), VM_PROT_WRITE, "max_prot still writable");
	/* cleanup */
	kr = mach_vm_deallocate(mach_task_self(), remap_address, remap_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_deallocate()");

#if defined(VM_MEMORY_ROSETTA)
	if (dlsym(RTLD_DEFAULT, "mach_vm_remap_new") == NULL) {
		T_PASS("vm_remap_new() is not present");
		goto skip_vm_remap_new_rw;
	}
	/* test vm_remap_new() of RW */
	before = *(uint32_t *)(uintptr_t)address;
	remap_address = 0;
	remap_size = size;
	cur_prot = VM_PROT_READ | VM_PROT_WRITE;
	max_prot = VM_PROT_READ | VM_PROT_WRITE;
	kr = mach_vm_remap_new(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    address,
	    FALSE,
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_remap_new()");
	if (kr == KERN_PROTECTION_FAILURE) {
		/* wrong but not a security issue... */
		goto skip_vm_remap_new_rw;
	}
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_remap_new()");
	if (!(cur_prot & VM_PROT_WRITE)) {
		T_LOG("vm_remap_new(): 0x%llx not writable %s/%s",
		    remap_address, prot_str[cur_prot], prot_str[max_prot]);
		T_ASSERT_FAIL("vm_remap_new() remapping not writable");
	}
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
	*(uint32_t *)(uintptr_t)remap_address = before + 1;
	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("vm_remap_new(): 0x%llx 0x%x -> 0x%x", address, before, after);
	*(uint32_t *)(uintptr_t)remap_address = before;
	if (before != after) {
		T_FAIL("vm_remap_new() bypassed copy-on-write");
	} else {
		T_PASS("vm_remap_new() did not bypass copy-on-write");
	}
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_DEFAULT, "cur_prot still writable");
	T_QUIET; T_ASSERT_EQ((info.max_protection & VM_PROT_WRITE), VM_PROT_WRITE, "max_prot still writable");
	/* cleanup */
	kr = mach_vm_deallocate(mach_task_self(), remap_address, remap_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_deallocate()");
skip_vm_remap_new_rw:
#else /* defined(VM_MEMORY_ROSETTA) */
	/* pre-BigSur SDK: no vm_remap_new() */
	T_LOG("No vm_remap_new() to test");
#endif /* defined(VM_MEMORY_ROSETTA) */

	/* test mach_make_memory_entry_64(VM_SHARE) of RW */
	before = *(uint32_t *)(uintptr_t)address;
	remap_size = size;
	mem_entry = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &remap_size,
	    address,
	    MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE,
	    &mem_entry,
	    MACH_PORT_NULL);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_make_memory_entry_64(VM_SHARE)");
	if (kr == KERN_PROTECTION_FAILURE) {
		/* wrong but not a security issue... */
		goto skip_mem_entry_vm_share_rw;
	}
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry_64(VM_SHARE)");
	T_QUIET; T_ASSERT_EQ(remap_size, size, "mem_entry(VM_SHARE) should cover whole mapping");
//	T_LOG("AFTER MAKE_MEM_ENTRY(VM_SHARE) 0x%llx...", address); fflush(stdout); fflush(stderr); getchar();
	remap_address = 0;
	kr = mach_vm_map(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,              /* mask */
	    VM_FLAGS_ANYWHERE,
	    mem_entry,
	    0,              /* offset */
	    FALSE,              /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_map()");
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
//	T_LOG("AFTER VM_MAP 0x%llx...", remap_address); fflush(stdout); fflush(stderr); getchar();
	*(uint32_t *)(uintptr_t)remap_address = before + 1;
//	T_LOG("AFTER WRITE 0x%llx...", remap_address); fflush(stdout); fflush(stderr); getchar();
	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("mem_entry(VM_SHARE): 0x%llx 0x%x -> 0x%x", address, before, after);
	*(uint32_t *)(uintptr_t)remap_address = before;
	if (before != after) {
		T_FAIL("mem_entry(VM_SHARE) bypassed copy-on-write");
	} else {
		T_PASS("mem_entry(VM_SHARE) did not bypass copy-on-write");
	}
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_DEFAULT, "cur_prot still writable");
	T_QUIET; T_ASSERT_EQ((info.max_protection & VM_PROT_WRITE), VM_PROT_WRITE, "max_prot still writable");
	/* cleanup */
	kr = mach_vm_deallocate(mach_task_self(), remap_address, remap_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_deallocate()");
	mach_port_deallocate(mach_task_self(), mem_entry);
skip_mem_entry_vm_share_rw:

	/* test mach_make_memory_entry_64() of RW */
	before = *(uint32_t *)(uintptr_t)address;
	remap_size = size;
	mem_entry = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &remap_size,
	    address,
	    VM_PROT_READ | VM_PROT_WRITE,
	    &mem_entry,
	    MACH_PORT_NULL);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry_64()");
	remap_address = 0;
	kr = mach_vm_map(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,              /* mask */
	    VM_FLAGS_ANYWHERE,
	    mem_entry,
	    0,              /* offset */
	    FALSE,              /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_map()");
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
	*(uint32_t *)(uintptr_t)remap_address = before + 1;
	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("mem_entry(): 0x%llx 0x%x -> 0x%x", address, before, after);
	*(uint32_t *)(uintptr_t)remap_address = before;
	/* check that region is no longer nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	if (before != after) {
		if (depth == 0) {
			T_PASS("mem_entry() honored copy-on-write");
		} else {
			T_FAIL("mem_entry() did not trigger copy-on_write");
		}
	} else {
		T_FAIL("mem_entry() did not honor copy-on-write");
	}
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_EQ(depth, 0, "no longer nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_DEFAULT, "cur_prot still writable");
	T_QUIET; T_ASSERT_EQ((info.max_protection & VM_PROT_WRITE), VM_PROT_WRITE, "max_prot still writable");
	/* cleanup */
	kr = mach_vm_deallocate(mach_task_self(), remap_address, remap_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_deallocate()");
	mach_port_deallocate(mach_task_self(), mem_entry);
}

T_DECL(copyoverwrite_submap_protection, "test copywrite vm region submap \
    protection", T_META_ALL_VALID_ARCHS(true))
{
	kern_return_t           kr;
	mach_vm_address_t       vmaddr;
	mach_vm_size_t          vmsize;
	natural_t               depth;
	vm_region_submap_short_info_data_64_t region_info;
	mach_msg_type_number_t  region_info_count;

	for (vmaddr = SHARED_REGION_BASE;
	    vmaddr < SHARED_REGION_BASE + SHARED_REGION_SIZE;
	    vmaddr += vmsize) {
		depth = 99;
		region_info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
		kr = mach_vm_region_recurse(mach_task_self(),
		    &vmaddr,
		    &vmsize,
		    &depth,
		    (vm_region_info_t) &region_info,
		    &region_info_count);
		if (kr == KERN_INVALID_ADDRESS) {
			break;
		}
		T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse(0x%llx)", vmaddr);
		T_ASSERT_EQ(region_info_count,
		    VM_REGION_SUBMAP_SHORT_INFO_COUNT_64,
		    "vm_region_recurse(0x%llx) count = %d expected %d",
		    vmaddr, region_info_count,
		    VM_REGION_SUBMAP_SHORT_INFO_COUNT_64);

		T_LOG("--> region: vmaddr 0x%llx depth %d prot 0x%x/0x%x",
		    vmaddr, depth, region_info.protection,
		    region_info.max_protection);
		if (depth == 0) {
			/* not a submap mapping: next mapping */
			continue;
		}
		if (vmaddr >= SHARED_REGION_BASE + SHARED_REGION_SIZE) {
			break;
		}
		kr = mach_vm_copy(mach_task_self(),
		    vmaddr,
		    vmsize,
		    vmaddr);
		if (kr == KERN_PROTECTION_FAILURE ||
		    kr == KERN_INVALID_ADDRESS) {
			T_PASS("vm_copy(0x%llx,0x%llx) expected prot error 0x%x (%s)",
			    vmaddr, vmsize, kr, mach_error_string(kr));
			continue;
		}
		T_ASSERT_MACH_SUCCESS(kr, "vm_copy(0x%llx,0x%llx) prot 0x%x",
		    vmaddr, vmsize, region_info.protection);
		depth = 0;
		region_info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
		kr = mach_vm_region_recurse(mach_task_self(),
		    &vmaddr,
		    &vmsize,
		    &depth,
		    (vm_region_info_t) &region_info,
		    &region_info_count);
		T_ASSERT_MACH_SUCCESS(kr, "m_region_recurse(0x%llx)", vmaddr);
		T_ASSERT_EQ(region_info_count,
		    VM_REGION_SUBMAP_SHORT_INFO_COUNT_64,
		    "vm_region_recurse() count = %d expected %d",
		    region_info_count, VM_REGION_SUBMAP_SHORT_INFO_COUNT_64);

		T_ASSERT_EQ(depth, 0, "vm_region_recurse(0x%llx): depth = %d expected 0",
		    vmaddr, depth);
		T_ASSERT_EQ((region_info.protection & VM_PROT_EXECUTE),
		    0, "vm_region_recurse(0x%llx): prot 0x%x",
		    vmaddr, region_info.protection);
	}
}

T_DECL(wire_text, "test wired text for rdar://problem/16783546 Wiring code in \
    the shared region triggers code-signing violations",
    T_META_ALL_VALID_ARCHS(true))
{
	uint32_t *addr, before, after;
	int retval;
	int saved_errno;
	kern_return_t kr;
	vm_address_t map_addr, remap_addr;
	vm_prot_t curprot, maxprot;

	addr = (uint32_t *)&printf;
#if __has_feature(ptrauth_calls)
	map_addr = (vm_address_t)(uintptr_t)ptrauth_strip(addr, ptrauth_key_function_pointer);
#else /* __has_feature(ptrauth_calls) */
	map_addr = (vm_address_t)(uintptr_t)addr;
#endif /* __has_feature(ptrauth_calls) */
	remap_addr = 0;
	kr = vm_remap(mach_task_self(), &remap_addr, 4096,
	    0,           /* mask */
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(), map_addr,
	    FALSE,           /* copy */
	    &curprot, &maxprot,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_remap error 0x%x (%s)",
	    kr, mach_error_string(kr));
	before = *addr;
	retval = mlock(addr, 4096);
	after = *addr;
	if (retval != 0) {
		saved_errno = errno;
		T_ASSERT_EQ(saved_errno, EPERM, "wire shared text error %d (%s), expected: %d",
		    saved_errno, strerror(saved_errno), EPERM);
	} else if (after != before) {
		T_ASSERT_FAIL("shared text changed by wiring at %p 0x%x -> 0x%x", (void *)addr, before, after);
	} else {
		T_PASS("wire shared text");
	}

	addr = (uint32_t *) &fprintf;
	before = *addr;
	retval = mlock(addr, 4096);
	after = *addr;
	if (retval != 0) {
		saved_errno = errno;
		T_ASSERT_EQ(saved_errno, EPERM, "wire shared text error %d (%s), expected: %d",
		    saved_errno, strerror(saved_errno), EPERM);
	} else if (after != before) {
		T_ASSERT_FAIL("shared text changed by wiring at %p 0x%x -> 0x%x", (void *)addr, before, after);
	} else {
		T_PASS("wire shared text");
	}

	addr = (uint32_t *) &testmain_wire_text;
	before = *addr;
	retval = mlock(addr, 4096);
	after = *addr;
	if (retval != 0) {
		saved_errno = errno;
		T_ASSERT_EQ(saved_errno, EPERM, "wire text error return error %d (%s)",
		    saved_errno, strerror(saved_errno));
	} else if (after != before) {
		T_ASSERT_FAIL("text changed by wiring at %p 0x%x -> 0x%x", (void *)addr, before, after);
	} else {
		T_PASS("wire text");
	}
}

T_DECL(mlock_max_prot_none, "test mlock() of max_prot=none memory, rdar://150030055",
    T_META_TAG_VM_PREFERRED)
{
	int err;
	kern_return_t kr;
	mach_vm_address_t addr = 0;
	kr = mach_vm_allocate(mach_task_self(), &addr, PAGE_SIZE, VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocate");
	kr = mach_vm_protect(mach_task_self(), addr, PAGE_SIZE, false /* set_max */, VM_PROT_NONE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "cur_prot = none");
	kr = mach_vm_protect(mach_task_self(), addr, PAGE_SIZE, true /* set_max */, VM_PROT_NONE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "max_prot = none");

	mach_vm_address_t query_addr = addr;
	mach_vm_size_t query_size = 0;
	uint32_t query_depth = 0;
	vm_region_submap_info_data_64_t info;
	mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(), &query_addr, &query_size, &query_depth,
	    (vm_region_recurse_info_t)&info, &info_count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region before");
	T_QUIET; T_ASSERT_EQ(info.object_id_full, 0ULL, "null object before");

	err = mlock((void *)addr, PAGE_SIZE);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "mlock() of max_prot=none");

	kr = mach_vm_region_recurse(mach_task_self(), &query_addr, &query_size, &query_depth,
	    (vm_region_recurse_info_t)&info, &info_count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region after");
	T_QUIET; T_ASSERT_NE(info.object_id_full, 0ULL, "non-null object after");

	T_PASS("mlock() of max_prot=none");
}

_Static_assert(_COMM_PAGE_BASE_ADDRESS != -1 && _COMM_PAGE_BASE_ADDRESS != 0, "unexpected commpage address");

T_DECL(remap_comm_page, "test remapping of the commpage - rdar://93177124",
    T_META_ALL_VALID_ARCHS(true))
{
	kern_return_t           kr;
	mach_vm_address_t       commpage_addr = (mach_vm_address_t)_COMM_PAGE_BASE_ADDRESS;
	mach_vm_address_t        remap_addr;
	mach_vm_size_t          vmsize;
	vm_prot_t               curprot = 0, maxprot = 0;

	T_LOG("Remapping commpage from 0x%llx", commpage_addr);
	vmsize = vm_kernel_page_size;
	remap_addr = 0;
	kr = mach_vm_remap(mach_task_self(),
	    &remap_addr,
	    vmsize,
	    0, /* mask */
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    commpage_addr,
	    TRUE, /* copy */
	    &curprot,
	    &maxprot,
	    VM_INHERIT_DEFAULT);
	if (kr == KERN_INVALID_ADDRESS) {
		T_SKIP("No mapping found at 0x%llx\n", commpage_addr);
		return;
	}
	T_ASSERT_MACH_SUCCESS(kr, "vm_remap() of commpage from 0x%llx to 0x%llx  curprot=%x, maxprot=%x", commpage_addr, remap_addr, curprot, maxprot);
}

T_DECL(vm_read_comm_page, "test vm_read from commpage")
{
	kern_return_t kr;
	mach_vm_address_t commpage_addr = (mach_vm_address_t)_COMM_PAGE_BASE_ADDRESS;
	mach_vm_size_t size = vm_kernel_page_size;
	vm_offset_t read_addr = 0;
	mach_msg_type_number_t read_size = 0;

	kr = mach_vm_read(mach_task_self(), commpage_addr, size, &read_addr, &read_size);

	if (kr == KERN_INVALID_ADDRESS) {
		T_SKIP("No mapping found at 0x%llx\n", commpage_addr);
		return;
	}
	if (commpage_addr < MACH_VM_MAX_ADDRESS) {
		// in macos arm64, the commpage is inside [min_offset:max_offset] so the small kernel-buffer optimization
		// takes effect. This allows vm_map_copyin_internal() to succeed even though the commpage region is mapped as PROT_NONE
		T_ASSERT_MACH_SUCCESS(kr, "mach_vm_read() of commpage from 0x%llx to 0x%lx  max=0x%llx (sz=%x)", commpage_addr, read_addr, MACH_VM_MAX_ADDRESS, read_size);
	} else {
#if __arm64__
		// in non-macos arm64 platforms, the commpage is outside [min_offset:max_offset] so the small kernel-buffer
		// optimization is skipped. Then vm_map_copyin_internal() fails since the region is mapped as PROT_NONE
		T_ASSERT_MACH_ERROR(kr, KERN_PROTECTION_FAILURE, "mach_vm_read() expected failure addr=0x%llx  max=0x%llx", commpage_addr, MACH_VM_MAX_ADDRESS);
#else // __arm64__
		// ... except in x86 where the commpage is a submap and not mapped as PROT_NONE, so vm_map_copyin_internal succeeds
		T_ASSERT_MACH_SUCCESS(kr, "mach_vm_read() of commpage from 0x%llx to 0x%lx  max=0x%llx (sz=%x)", commpage_addr, read_addr, MACH_VM_MAX_ADDRESS, read_size);
#endif // __arm64__
	}
}

/* rdar://132439059 */
T_DECL(mach_vm_remap_new_task_read_port,
    "Ensure shared, writable mappings cannot be created with a process's task read port using mach_vm_remap_new",
    T_META_TAG_VM_PREFERRED,
    T_META_RUN_CONCURRENTLY(true))
{
	mach_vm_address_t private_data = 0;
	pid_t pid = -1;
	int fds[2];
	uint32_t depth = 9999;
	mach_vm_size_t size = PAGE_SIZE;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
	vm_region_submap_info_data_64_t info;
	kern_return_t kr = KERN_FAILURE;
	int ret = -1;

	kr = mach_vm_allocate(mach_task_self(), &private_data, size, VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_allocate");

	ret = pipe(fds);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pipe");

	pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) {
		char data[2];
		ssize_t nbytes_read = -1;

		/* Close write end of the pipe */
		ret = close(fds[1]);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "child: close write end");

		/* Check that the permissions are VM_PROT_DEFAULT/VM_PROT_ALL */
		kr = mach_vm_region_recurse(mach_task_self(),
		    &private_data,
		    &size,
		    &depth,
		    (vm_region_recurse_info_t)&info,
		    &count);
		T_ASSERT_MACH_SUCCESS(kr, "child: mach_vm_region_recurse");
		T_EXPECT_EQ_INT(info.protection, VM_PROT_DEFAULT, "child: current protection is VM_PROT_DEFAULT");
		T_EXPECT_EQ_INT(info.max_protection, VM_PROT_ALL, "child: maximum protextion is VM_PROT_ALL");

		/* The child tries to read data from the pipe (that never comes) */
		nbytes_read = read(fds[0], data, 2);
		T_QUIET; T_EXPECT_EQ_LONG(nbytes_read, 0L, "child: read 0 bytes");

		exit(0);
	} else {
		mach_port_t read_port = MACH_PORT_NULL;
		mach_vm_address_t remap_addr = 0;
		int status;

		/* Close read end of the pipe */
		ret = close(fds[0]);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "close read end");

		/* Get a read port */
		ret = task_read_for_pid(mach_task_self(), pid, &read_port);
		T_ASSERT_POSIX_SUCCESS(ret, "parent: task_read_for_pid");

		/* Make a shared mapping with the child's data */
		vm_prot_t cur_prot = VM_PROT_NONE;
		vm_prot_t max_prot = VM_PROT_NONE;
		kr = mach_vm_remap_new(
			mach_task_self(),
			&remap_addr,
			size,
			0, /* mask */
			VM_FLAGS_ANYWHERE,
			read_port,
			private_data,
			FALSE, /* copy */
			&cur_prot,
			&max_prot,
			VM_INHERIT_DEFAULT);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "parent: mach_vm_remap_new");

		/* Check that permissions of the remapped region are VM_PROT_NONE */
		kr = mach_vm_region_recurse(mach_task_self(),
		    &remap_addr,
		    &size,
		    &depth,
		    (vm_region_recurse_info_t)&info,
		    &count);
		T_ASSERT_MACH_SUCCESS(kr, "parent: mach_vm_region_recurse");
		T_EXPECT_EQ_INT(info.protection, VM_PROT_NONE, "parent: current protection is VM_PROT_NONE");
		T_EXPECT_EQ_INT(info.max_protection, VM_PROT_NONE, "parent: maximum protextion is VM_PROT_NONE");

		/* Tell the child it is done and can exit. */
		ret = close(fds[1]);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "parent: close write end");

		/* Clean up the child */
		ret = waitpid(pid, &status, 0);
		T_EXPECT_EQ_INT(ret, pid, "waitpid: child was stopped or terminated");
	}
}


static void
zsm_vm_map(size_t size,
    int flags,
    mem_entry_name_port_t port,
    memory_object_offset_t offset,
    boolean_t copy,
    vm_prot_t cur_protection,
    vm_prot_t max_protection,
    vm_inherit_t inheritance,
    mach_vm_address_t *out_addr,
    size_t *out_size
    )
{
	mach_vm_address_t addr_info = 0;
	if (!(flags & VM_FLAGS_ANYWHERE)) {
		flags |= VM_FLAGS_ANYWHERE;
	}

	cur_protection &= max_protection;
	kern_return_t kr = mach_vm_map(mach_task_self(), &addr_info, size, 0, flags, port, offset,
	    copy, cur_protection, max_protection, inheritance);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_map");
	T_LOG("mapped memory at %llx", addr_info);

	*out_addr = addr_info;
	*out_size = size;
}

static mem_entry_name_port_t
zsm_vm_mach_make_memory_entry(mach_vm_address_t addr, size_t size, int flags,
    mem_entry_name_port_t parent,
    kern_return_t expected_kr, bool discard)
{
	T_LOG("making memory entry for addr=%llx  size=%zx", addr, size);
	mem_entry_name_port_t port = 0;
	kern_return_t kr = mach_make_memory_entry(mach_task_self(), &size, addr, flags, &port, parent);
	T_ASSERT_EQ(kr, expected_kr, "mach_make_memory_entry expected return %d", kr);
	if (kr == KERN_SUCCESS) {
		T_ASSERT_NE(port, 0, "got non zero port");
		if (discard) {
			mach_port_deallocate(mach_task_self(), port);
			port = 0;
		}
	}
	return port;
}

T_DECL(memory_entry_zero_sized,
    "Test that creating a zero-sized memory-entry with parent fails correctly")
{
	mach_vm_address_t addr = 0;
	size_t size = 0;
	kern_return_t kr;
	zsm_vm_map(0xa7c000,
	    0,        /* flags */
	    0,        /* port */
	    0,        /* offset */
	    0,        /* copy */
	    VM_PROT_EXECUTE, VM_PROT_EXECUTE,
	    0x1,         /* inheritance */
	    &addr, &size);
	mem_entry_name_port_t parent_entry = zsm_vm_mach_make_memory_entry(addr, size, 0, 0, KERN_SUCCESS, false);

	zsm_vm_mach_make_memory_entry(0, 0, 0, parent_entry, KERN_INVALID_ARGUMENT, true);
	zsm_vm_mach_make_memory_entry(0, 1, 0, parent_entry, KERN_SUCCESS, true);
	zsm_vm_mach_make_memory_entry(1, 0, 0, parent_entry, KERN_SUCCESS, true);

	zsm_vm_mach_make_memory_entry(PAGE_SIZE, 0, 0, parent_entry, KERN_INVALID_ARGUMENT, true);
	zsm_vm_mach_make_memory_entry(PAGE_SIZE, 1, 0, parent_entry, KERN_SUCCESS, true);
	zsm_vm_mach_make_memory_entry(PAGE_SIZE + 1, 0, 0, parent_entry, KERN_SUCCESS, true);

	kr = mach_port_deallocate(mach_task_self(), parent_entry);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate");
	kr = mach_vm_deallocate(mach_task_self(), addr, size);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate");
}

T_DECL(memory_entry_null_obj,
    "Test creating a memory-entry with null vm_object")
{
	mach_vm_address_t addr = 0;
	size_t size = 0;
	kern_return_t kr = 0;
	uint8_t value = 0;

	// create an allocation with vm_object == NULL
	zsm_vm_map(0x604000, /* size */
	    0,           /* flags */
	    0,           /* port */
	    0,           /* offset */
	    TRUE,         /* copy */
	    VM_PROT_NONE, VM_PROT_NONE,
	    0x0,         /* inheritance */
	    &addr, &size);

	// verify it's NONE
	bool read_success = try_read_byte(addr, &value, &kr);
	T_ASSERT_FALSE(read_success, "can't read from NONE address");
	bool write_succeded = try_write_byte(addr, 42, &kr);
	T_ASSERT_FALSE(write_succeded, "can't write to NONE address");

	// size 0 entry of the allocated memory - should fail
	zsm_vm_mach_make_memory_entry(addr, /*size=*/ 0, /*flags=*/ 0x0, /*parent=*/ 0x0, KERN_INVALID_ARGUMENT, true);

	// trying to get a 'copy' entry of a PROT_NONE entry
	zsm_vm_mach_make_memory_entry(addr, size, /*flags=*/ 0x0, /*parent=*/ 0x0, KERN_PROTECTION_FAILURE, true);

	// get a 'share' entry of a PROT_NONE entry and remap it
	mem_entry_name_port_t np = zsm_vm_mach_make_memory_entry(addr, size, MAP_MEM_VM_SHARE, 0x0, KERN_SUCCESS, false);

	mach_vm_address_t m_addr = 0;
	size_t m_size = 0;
	zsm_vm_map(size,
	    0,            /* size */
	    np,
	    0,            /* offset */
	    FALSE,        /* copy */
	    VM_PROT_NONE, VM_PROT_NONE,
	    0x0,                         /* inheritance */
	    &m_addr, &m_size);

	// try to accessremapped area
	read_success = try_read_byte(m_addr, &value, &kr);
	T_ASSERT_FALSE(read_success, "can't read from NONE address");
	write_succeded = try_write_byte(m_addr, 42, &kr);
	T_ASSERT_FALSE(write_succeded, "can't write to NONE address");

	kr = mach_port_deallocate(mach_task_self(), np);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate");
	kr = mach_vm_deallocate(mach_task_self(), addr, size);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate");
	kr = mach_vm_deallocate(mach_task_self(), m_addr, m_size);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate mapped");
}

#if __arm64e__
#define TARGET_CPU_ARM64E true
#else
#define TARGET_CPU_ARM64E false
#endif

T_DECL(vm_region_recurse_tpro_info,
    "Ensure metadata returned by vm_region_recurse correct reflects TPRO status",
    T_META_ENABLED(TARGET_CPU_ARM64E),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true))
{
	T_SETUPBEGIN;

	/* First things first, do nothing unless we're TPRO enabled */
	if (!(os_security_config_get() & OS_SECURITY_CONFIG_TPRO)) {
		T_SKIP("Skipping because we're not running under TPRO");
		return;
	}

	/* Given an allocation from dyld's heap */
	const char* tpro_allocation = _dyld_get_image_name(0);

	/* And an allocation from our own heap (which is not TPRO) */
	mach_vm_address_t non_tpro_allocation;
	mach_vm_size_t alloc_size = PAGE_SIZE;
	kern_return_t kr = mach_vm_allocate(
		mach_task_self(),
		&non_tpro_allocation,
		alloc_size,
		VM_FLAGS_ANYWHERE );
	T_ASSERT_MACH_SUCCESS(kr, "Allocated non-TPRO region");
	/* (And write to it to be sure we populate a VM object) */
	memset((uint8_t*)non_tpro_allocation, 0, alloc_size);

	T_SETUPEND;

	/* When we query the attributes of the region covering the TPRO-enabled buffer */
	mach_vm_address_t addr = (mach_vm_address_t)tpro_allocation;
	mach_vm_size_t addr_size = 16;
	uint32_t nesting_depth = UINT_MAX;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	vm_region_submap_info_data_64_t region_info;
	kr = vm_region_recurse_64(mach_task_self(), (vm_address_t*)&addr, (vm_size_t*)&addr_size, &nesting_depth, (vm_region_recurse_info_t)&region_info, &count);

	/* Then our metadata confirms that the region contains a TPRO entry */
	T_ASSERT_MACH_SUCCESS(kr, "Query TPRO-enabled region");
	T_ASSERT_TRUE(region_info.flags & VM_REGION_FLAG_TPRO_ENABLED, "Expected metadata to reflect a TPRO entry");

	/* And when we query the same thing via the 'short' info */
	addr = (mach_vm_address_t)tpro_allocation;
	addr_size = alloc_size;
	nesting_depth = UINT_MAX;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	vm_region_submap_short_info_data_64_t short_info;
	kr = mach_vm_region_recurse(mach_task_self(), (mach_vm_address_t*)&addr, (mach_vm_size_t*)&addr_size, &nesting_depth, (vm_region_info_t)&short_info, &count);

	/* Then the short metadata also confirms that the region contains a TPRO entry */
	T_ASSERT_MACH_SUCCESS(kr, "Query TPRO-enabled region");
	T_ASSERT_TRUE(short_info.flags & VM_REGION_FLAG_TPRO_ENABLED, "Expected metadata to reflect a TPRO entry");

	/* And when we query the attributes of the region covering the non-TPRO allocation */
	addr = non_tpro_allocation;
	addr_size = alloc_size;
	nesting_depth = UINT_MAX;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	memset(&region_info, 0, sizeof(region_info));
	kr = mach_vm_region_recurse(mach_task_self(), (mach_vm_address_t*)&addr, (mach_vm_size_t*)&addr_size, &nesting_depth, (vm_region_info_t)&region_info, &count);

	/* Then our metadata confirm that the region does not contain a TPRO entry */
	T_ASSERT_MACH_SUCCESS(kr, "Query non-TPRO region");
	T_ASSERT_FALSE(region_info.flags & VM_REGION_FLAG_TPRO_ENABLED, "Expected metadata to reflect no TPRO entry");

	/* And when we query the same thing via the 'short' info */
	addr = non_tpro_allocation;
	addr_size = alloc_size;
	nesting_depth = UINT_MAX;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	memset(&short_info, 0, sizeof(short_info));
	kr = mach_vm_region_recurse(mach_task_self(), (mach_vm_address_t*)&addr, (mach_vm_size_t*)&addr_size, &nesting_depth, (vm_region_info_t)&short_info, &count);

	/* Then the short metadata also confirms that the region does not contain a TPRO entry */
	T_ASSERT_MACH_SUCCESS(kr, "Query non-TPRO region");
	T_ASSERT_FALSE(short_info.flags & VM_REGION_FLAG_TPRO_ENABLED, "Expected metadata to reflect no TPRO entry");

	/* Cleanup */
	kr = mach_vm_deallocate(mach_task_self(), non_tpro_allocation, alloc_size);
	T_ASSERT_MACH_SUCCESS(kr, "deallocate memory");
}

T_DECL(vm_region_recurse_jit_info,
    "Ensure metadata returned by vm_region_recurse correct reflects JIT status",
    XNU_T_META_SOC_SPECIFIC,
    /* Only attempt to run on macOS so we don't need to worry about JIT policy */
    T_META_ENABLED(TARGET_OS_OSX),
    T_META_ASROOT(true))
{
	/* T_META_ENABLED is not respected at-desk, so check again */
#if !TARGET_OS_OSX
	T_SKIP("This test is not supported on embedded platforms");
#endif /* !TARGET_OS_OSX */

	T_SETUPBEGIN;

	/* Given a JIT region */
	mach_vm_size_t alloc_size = PAGE_SIZE * 4;
	void* jit_region = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
	T_ASSERT_NE_PTR(jit_region, MAP_FAILED, "MAP_JIT");

	/* And a non-JIT region */
	mach_vm_address_t non_jit_allocation;
	kern_return_t kr = mach_vm_allocate(
		mach_task_self(),
		&non_jit_allocation,
		alloc_size,
		VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "Allocated non-JIT region");
	/* (And write to it to be sure we populate a VM object) */
	memset((uint8_t*)non_jit_allocation, 0, alloc_size);

	T_SETUPEND;

	/* When we query the attributes of the region covering the JIT-enabled buffer */
	mach_vm_address_t addr = (mach_vm_address_t)jit_region;
	mach_vm_size_t addr_size = alloc_size;
	uint32_t nesting_depth = UINT_MAX;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	vm_region_submap_info_data_64_t region_info;
	kr = vm_region_recurse_64(mach_task_self(), (vm_address_t*)&addr, (vm_size_t*)&addr_size, &nesting_depth, (vm_region_recurse_info_t)&region_info, &count);

	/* Then our metadata confirms that the region contains a JIT entry */
	T_ASSERT_MACH_SUCCESS(kr, "Query JIT-enabled region");
	T_ASSERT_TRUE(region_info.flags & VM_REGION_FLAG_JIT_ENABLED, "Expected metadata to reflect a JIT entry");

	/* And when we query the same thing via the 'short' info */
	addr = (mach_vm_address_t)jit_region;
	addr_size = alloc_size;
	nesting_depth = UINT_MAX;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	vm_region_submap_short_info_data_64_t short_info;
	kr = mach_vm_region_recurse(mach_task_self(), (mach_vm_address_t*)&addr, (mach_vm_size_t*)&addr_size, &nesting_depth, (vm_region_info_t)&short_info, &count);

	/* Then the short metadata also confirms that the region contains a JIT entry */
	T_ASSERT_MACH_SUCCESS(kr, "Query JIT-enabled region");
	T_ASSERT_TRUE(short_info.flags & VM_REGION_FLAG_JIT_ENABLED, "Expected metadata to reflect a JIT entry");

	/* And when we query the attributes of the region covering the non-JIT allocation */
	addr = non_jit_allocation;
	addr_size = alloc_size;
	nesting_depth = UINT_MAX;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	memset(&region_info, 0, sizeof(region_info));
	kr = mach_vm_region_recurse(mach_task_self(), (mach_vm_address_t*)&addr, (mach_vm_size_t*)&addr_size, &nesting_depth, (vm_region_info_t)&region_info, &count);

	/* Then our metadata confirm that the region does not contain a JIT entry */
	T_ASSERT_MACH_SUCCESS(kr, "Query non-JIT region");
	T_ASSERT_FALSE(region_info.flags & VM_REGION_FLAG_JIT_ENABLED, "Expected metadata to reflect no JIT entry");

	/* And when we query the same thing via the 'short' info */
	addr = non_jit_allocation;
	addr_size = alloc_size;
	nesting_depth = UINT_MAX;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	memset(&short_info, 0, sizeof(short_info));
	kr = mach_vm_region_recurse(mach_task_self(), (mach_vm_address_t*)&addr, (mach_vm_size_t*)&addr_size, &nesting_depth, (vm_region_info_t)&short_info, &count);

	/* Then the short metadata also confirms that the region does not contain a JIT entry */
	T_ASSERT_MACH_SUCCESS(kr, "Query non-JIT region");
	T_ASSERT_FALSE(short_info.flags & VM_REGION_FLAG_JIT_ENABLED, "Expected metadata to reflect no JIT entry");

	/* Cleanup */
	kr = mach_vm_deallocate(mach_task_self(), non_jit_allocation, alloc_size);
	T_ASSERT_MACH_SUCCESS(kr, "deallocate memory");
}

static void
check_manual_remap(bool entry_is_copy, bool map_is_copy, bool pre_fault, bool change_first_in_copy)
{
	T_LOG("** case: entry_is_copy=%d,  map_is_copy=%d,  pre_fault=%d  change_first_in_copy=%d",
	    (int)entry_is_copy, (int)map_is_copy, (int)pre_fault, (int)change_first_in_copy);
	kern_return_t kr;
	mach_vm_address_t addr_A = 0;
	mach_vm_size_t size = 2 * PAGE_SIZE;

	// allocate memory
	kr = mach_vm_allocate(mach_task_self(), &addr_A, size, VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_allocate");
	T_LOG("Address A: %llx", addr_A);

	// fault and set initial value
	uint32_t* ptr_A = (uint32_t*)addr_A;
	uint32_t expected_value_in_A = 0;
	if (pre_fault) {
		*ptr_A = 1;
		expected_value_in_A = 1;
	}

	// create mem-entry
	mem_entry_name_port_t mem_ent = 0;
	mach_vm_size_t entry_size = size;
	vm_prot_t flags = MAP_MEM_USE_DATA_ADDR | VM_PROT_DEFAULT;
	if (entry_is_copy) {
		flags |= MAP_MEM_VM_COPY;
	}
	kr = mach_make_memory_entry_64(mach_task_self(), &entry_size, addr_A, flags, &mem_ent, MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry");
	T_ASSERT_EQ(entry_size, size, "memory-entry size same as requested size");

	// remap it
	mach_vm_offset_t addr_B = 0;
	kr = mach_vm_map(mach_task_self(), &addr_B, size, /*mask=*/ 0,
	    VM_FLAGS_ANYWHERE, mem_ent, /*offset=*/ 0,
	    /*copy=*/ map_is_copy,
	    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_map");
	T_LOG("Address B: %llx", addr_B);

	// verify copy/share
	uint32_t* ptr_B = (uint32_t*)addr_B;

	// the remap should be CoW if either or both entry or remap requested it to be copy
	bool cow = entry_is_copy || map_is_copy;
	if (change_first_in_copy) {
		// change value from B
		uint32_t value_in_B = *ptr_B;
		T_ASSERT_EQ(value_in_B, expected_value_in_A, "(before step2-1) value in B is the same as in A");
		*ptr_B = 2;
		// check value in A
		uint32_t value_in_A_step2 = *ptr_A;
		if (cow) { // CoW option, only remapped copy should change
			T_ASSERT_EQ(value_in_A_step2, expected_value_in_A, "(step2-1) value in CoW is unchanged");
		} else { // share option, should be the same value
			T_ASSERT_EQ(value_in_A_step2, 2, "(step2-1) value in the share A same as in changed B");
		}

		// now change value in A
		*ptr_A = 3;
		uint32_t value_in_B_step3 = *ptr_B;
		// check what happened to value in B
		if (cow) { // CoW option, B should not change
			T_ASSERT_EQ(value_in_B_step3, 2, "(step3-1) value in CoW unchanged");
		} else { // share option, B should be the same as A
			T_ASSERT_EQ(value_in_B_step3, 3, "(step3-1) value in the share B is the same as in changed A");
		}
	} else { /* change_first_in_copy */
		// change value from A
		*ptr_A = 4;
		// check value in B
		uint32_t value_in_B_step2 = *ptr_B;
		if (cow) { // CoW option, B should not change
			T_ASSERT_EQ(value_in_B_step2, expected_value_in_A, "(step2-2) value CoW is unchanged");
		} else { // share option, B should mirror change in A
			T_ASSERT_EQ(value_in_B_step2, 4, "(step2-2) value in share B same as iun changed A");
		}

		// now change value in B
		*ptr_B = 5;
		uint32_t value_in_A_step3 = *ptr_A;
		if (cow) { // CoW option, A should not change from step2
			T_ASSERT_EQ(value_in_A_step3, 4, "(step3-2) value CoW is unchanged");
		} else { // share option, A should mirror B
			T_ASSERT_EQ(value_in_A_step3, 5, "(step3-2) value in share A is the same as in changed B");
		}
	}

	// cleanup
	kr = mach_port_deallocate(mach_task_self(), mem_ent);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate memory entry");
	kr = mach_vm_deallocate(mach_task_self(), addr_A, size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate A");
	kr = mach_vm_deallocate(mach_task_self(), addr_B, size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate B");
	T_LOG("\n");
}


// create named-entry in either copy/share and then map it in either copy/share
// then verify that CoW works
T_DECL(manual_remap_all_copy_permutations,
    "Test all 4 permutations of copy argument to making a memory entry and remapping it")
{
	for (int change_first_in_copy = 0; change_first_in_copy <= 1; ++change_first_in_copy) {
		for (int pre_fault = 0; pre_fault <= 1; ++pre_fault) {
			check_manual_remap(true, true, (bool)pre_fault, change_first_in_copy);
			check_manual_remap(true, false, (bool)pre_fault, change_first_in_copy);
			check_manual_remap(false, true, (bool)pre_fault, change_first_in_copy);
			check_manual_remap(false, false, (bool)pre_fault, change_first_in_copy);
		}
	}
}

void
make_memory_entry_clipping(bool pre_fault, bool first_entry_is_share, bool expect_clipped_second)
{
	T_LOG("case pre_fault=%d  first_entry_is_share=%d", (int)pre_fault, (int)first_entry_is_share);
	kern_return_t kr;
	mach_vm_address_t addr = 0;
	mach_vm_size_t size = 2 * PAGE_SIZE;

	// allocate memory
	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_allocate");

	if (pre_fault) {
		uint32_t* ptr = (uint32_t*)addr;
		*ptr = 1;
	}

	// first memory entry maybe does the clipping to 1 page
	mem_entry_name_port_t mem_ent1 = 0;
	mach_vm_size_t entry1_size = 1 * PAGE_SIZE;
	vm_prot_t flags = MAP_MEM_USE_DATA_ADDR | VM_PROT_DEFAULT;
	if (first_entry_is_share) {
		flags |= MAP_MEM_VM_SHARE;
	} else {
		flags |= MAP_MEM_VM_COPY;
	}
	kr = mach_make_memory_entry_64(mach_task_self(), &entry1_size, addr, flags, &mem_ent1, MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "first mach_make_memory_entry");
	T_ASSERT_EQ(entry1_size, (mach_vm_size_t)(1 * PAGE_SIZE), "memory-entry size same as requested size");

	// now try to make an entry of 2 pages
	mem_entry_name_port_t mem_ent2 = 0;
	mach_vm_size_t entry2_size = 2 * PAGE_SIZE;
	kr = mach_make_memory_entry_64(mach_task_self(), &entry2_size, addr,
	    MAP_MEM_USE_DATA_ADDR | VM_PROT_DEFAULT,
	    &mem_ent2, MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "second mach_make_memory_entry");
	// requested 2 pages but got 1
	mach_vm_size_t expected_size = expect_clipped_second ? (1 * PAGE_SIZE) : (2 * PAGE_SIZE);
	T_EXPECT_EQ(entry2_size, expected_size, "second memory-entry is %s", expect_clipped_second ? "clipped" : "not clipped");

	// cleanup
	kr = mach_port_deallocate(mach_task_self(), mem_ent1);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate memory entry1");
	kr = mach_port_deallocate(mach_task_self(), mem_ent2);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate memory entry2");
	kr = mach_vm_deallocate(mach_task_self(), addr, size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate");
	T_LOG("\n");
}

T_DECL(make_memory_entry_clipping,
    "Test current behaviour of clipping and single-object named-entries")
{
	// if the first named-entry is share, clipping does NOT occurs in vm_map_remap_extract
	// and not related to pre-faulting
	make_memory_entry_clipping(false, true, false);
	make_memory_entry_clipping(true, true, false);
	// if the first named-entry is copy, clipping occurs only if we pre-fault.
	// The fault causes the entry to have a non-null object. In that case the range lock needs to
	// setup-cow, which locks exclusive and clips
	make_memory_entry_clipping(true, false, true);
	make_memory_entry_clipping(false, false, false);
}

T_DECL(vm_read_overwrite_to_wired, "test overwriting wired mapping - \
    rdar://169034000",
    T_META_ALL_VALID_ARCHS(true))
{
	kern_return_t           kr;
	mach_port_t             obj_port = MACH_PORT_NULL;
	mach_vm_address_t       vmaddr1, vmaddr2;
	mach_vm_size_t          vmsize1, readsize;
	int                     ret;

	vmsize1 = 128 * 1024;
	kr = mach_memory_object_memory_entry_64(mach_host_self(),
	    /* internal */ TRUE,
	    vmsize1,
	    VM_PROT_DEFAULT,
	    MACH_PORT_NULL,
	    &obj_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "memory_object_memory_entry_64()");
	vmaddr1 = 0;
	kr = mach_vm_map(mach_task_self(),
	    &vmaddr1,
	    vmsize1,
	    /* mask */ 0,
	    VM_FLAGS_ANYWHERE,
	    obj_port,
	    /* offset */ 0,
	    /* copy */ FALSE,
	    VM_PROT_DEFAULT,
	    VM_PROT_DEFAULT,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_map()");
	memset((void *)(uintptr_t)vmaddr1, 0x41, vmsize1);
	ret = mlock((void *)(uintptr_t)vmaddr1, (size_t)vmsize1);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "mlock()");

	vmaddr2 = 0;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr2,
	    vmsize1,
	    VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");
	memset((void *)(uintptr_t)vmaddr2, 0x42, vmsize1);

	readsize = 0;
	kr = mach_vm_read_overwrite(mach_task_self(),
	    /* src */ vmaddr2,
	    vmsize1,
	    /* dst */ vmaddr1,
	    &readsize);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_read_overwrite()");

	unsigned char *cp = (unsigned char *)(uintptr_t)vmaddr1;
	for (int i = 0; i < vmsize1; i++) {
		T_QUIET;
		T_ASSERT_EQ(cp[i], 0x42, "vmaddr1[%d] = 0x%x instead of 0x%x",
		    i, cp[i], 0x42);
	}

	kr = mach_port_deallocate(mach_task_self(), obj_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_deallocate()");
}
