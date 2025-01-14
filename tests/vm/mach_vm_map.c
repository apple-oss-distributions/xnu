#include <darwintest.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdlib.h>

T_GLOBAL_META(T_META_ALL_VALID_ARCHS(true));

static struct mo_spec {
	int         flags;
	const char *s;
} mo_specs[] = {
#define E(f)    { f, #f }
	E(0),
	E(MAP_MEM_VM_COPY),
	E(MAP_MEM_VM_SHARE),
	E(MAP_MEM_USE_DATA_ADDR),
	E(MAP_MEM_VM_COPY | MAP_MEM_USE_DATA_ADDR),
	E(MAP_MEM_VM_SHARE | MAP_MEM_USE_DATA_ADDR),
	{ },
#undef E
};

struct range_spec {
	mach_vm_offset_t start;
	mach_vm_offset_t end;
};

static const mach_vm_offset_t  sz16k     = 16 << 10;
static mach_vm_address_t       scratch_addr = 0;
static const mach_vm_size_t    scratch_size = 3 * sz16k;
static const mach_vm_offset_t  mo_offset = sz16k - 128;
static const mach_vm_size_t    mo_size   = sz16k + 256;

static struct range_spec *
range_specs(void)
{
	struct range_spec array[] = {
		{ 0, 64, },
		{ 0, 128, },
		{ 0, 256, },
		{ 0, PAGE_SIZE, },
		{ 0, PAGE_SIZE + 64, },
		{ 0, 2 * PAGE_SIZE - 64 },
		{ 0, 2 * PAGE_SIZE },
		{ 64, PAGE_SIZE, },
		{ 64, PAGE_SIZE + 64, },
		{ 64, 2 * PAGE_SIZE - 64 },
		{ 64, 2 * PAGE_SIZE },
		{ PAGE_SIZE - 64, PAGE_SIZE, },
		{ PAGE_SIZE - 64, PAGE_SIZE + 64, },
		{ PAGE_SIZE - 64, 2 * PAGE_SIZE - 64 },
		{ PAGE_SIZE - 64, 2 * PAGE_SIZE },
		{ PAGE_SIZE, PAGE_SIZE + 64, },
		{ PAGE_SIZE, 2 * PAGE_SIZE - 64 },
		{ PAGE_SIZE, 2 * PAGE_SIZE },
		{ PAGE_SIZE + 64, 2 * PAGE_SIZE - 64 },
		{ PAGE_SIZE + 64, 2 * PAGE_SIZE },
		{ 0, sz16k + 64, },
		{ 0, sz16k + 128, },
		{ 0, sz16k + 256, },
		{ 0, sz16k + PAGE_SIZE, },
		{ 0, sz16k + PAGE_SIZE + 64, },
		{ 0, sz16k + 2 * PAGE_SIZE - 64 },
		{ 0, sz16k + 2 * PAGE_SIZE },
		{ 64, sz16k + PAGE_SIZE, },
		{ 64, sz16k + PAGE_SIZE + 64, },
		{ 64, sz16k + 2 * PAGE_SIZE - 64 },
		{ 64, sz16k + 2 * PAGE_SIZE },
		{ PAGE_SIZE - 64, sz16k + PAGE_SIZE, },
		{ PAGE_SIZE - 64, sz16k + PAGE_SIZE + 64, },
		{ PAGE_SIZE - 64, sz16k + 2 * PAGE_SIZE - 64 },
		{ PAGE_SIZE - 64, sz16k + 2 * PAGE_SIZE },
		{ PAGE_SIZE, sz16k +      PAGE_SIZE + 64, },
		{ PAGE_SIZE, sz16k +      2 * PAGE_SIZE - 64 },
		{ PAGE_SIZE, sz16k +      2 * PAGE_SIZE },
		{ PAGE_SIZE + 64, sz16k +      2 * PAGE_SIZE - 64 },
		{ PAGE_SIZE + 64, sz16k +      2 * PAGE_SIZE },
		{ },
	};
	struct range_spec *ret;

	ret = malloc(sizeof(array));
	memcpy(ret, array, sizeof(array));
	return ret;
}

static void
mach_vm_map_unaligned_test(
	int               mo_flags,
	int               vmflags,
	mach_vm_offset_t  map_offset,
	mach_vm_size_t    map_size)
{
	const int         tag = VM_MAKE_TAG(VM_MEMORY_SCENEKIT);
	mach_vm_address_t map_addr;
	kern_return_t     kr;
	mach_vm_size_t    size;
	mach_port_t       mo_port;
	bool              should_fail = false;
	mach_vm_offset_t  used_offset_for_size;
	mach_vm_offset_t  mo_start;
	mach_vm_offset_t  mo_end;

	size = mo_size;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &size, scratch_addr + mo_offset, VM_PROT_DEFAULT | mo_flags,
	    &mo_port, MACH_PORT_NULL);

	if (vmflags & VM_FLAGS_RETURN_DATA_ADDR) {
		used_offset_for_size = map_offset;
		if (mo_flags & MAP_MEM_USE_DATA_ADDR) {
			used_offset_for_size += mo_offset;
		}
	} else {
		used_offset_for_size = 0;
	}

	if (mo_flags & MAP_MEM_USE_DATA_ADDR) {
		mo_start = mo_offset;
		mo_end   = mo_offset + mo_size;
	} else {
		mo_start = trunc_page(mo_offset);
		mo_end   = round_page(mo_offset + mo_size);
	}

	if (round_page(used_offset_for_size + map_size) > round_page(mo_offset + mo_size)) {
		should_fail = true;
	}
	if ((map_offset & PAGE_MASK) &&
	    !(vmflags & VM_FLAGS_RETURN_DATA_ADDR) &&
	    !(mo_flags & (MAP_MEM_VM_COPY | MAP_MEM_VM_SHARE))) {
		should_fail = true;
	}


	T_QUIET; T_ASSERT_MACH_SUCCESS(kr,
	    "made memory entry for [%p + %#llx, %p + %#llx), size = %lld",
	    (void *)scratch_addr, map_offset,
	    (void *)scratch_addr, map_size, size);
	if (mo_flags & MAP_MEM_USE_DATA_ADDR) {
		T_QUIET; T_EXPECT_EQ(size, (mo_offset & PAGE_MASK) + mo_size, "check memory entry's size");
	} else {
		T_QUIET; T_EXPECT_EQ(size, round_page((mo_offset & PAGE_MASK) + mo_size), "check memory entry's size");
	}

	map_addr = 0;
	kr = mach_vm_map(mach_task_self(), &map_addr, map_size, 0,
	    tag | vmflags, mo_port, map_offset, true,
	    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	if (should_fail) {
		T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT,
		    "mach_vm_map(mo_port, [%#llx, %#llx) of [%#llx, %#llx) = %p",
		    mo_start + map_offset, mo_start + map_offset + map_size,
		    mo_start, mo_end, (void *)map_addr);
	} else {
		T_EXPECT_MACH_SUCCESS(kr,
		    "mach_vm_map(mo_port, [%#llx, %#llx) of [%#llx, %#llx) = %p",
		    mo_start + map_offset, mo_start + map_offset + map_size,
		    mo_start, mo_end, (void *)map_addr);
	}

	if (kr == KERN_SUCCESS) {
		vm_region_basic_info_data_64_t info;
		mach_msg_type_number_t         icount = VM_REGION_BASIC_INFO_COUNT_64;
		mach_vm_address_t              want_addr, r_addr;
		mach_vm_size_t                 want_size, r_size;
		uint32_t                       want_data;

		if (vmflags & VM_FLAGS_RETURN_DATA_ADDR) {
			T_QUIET; T_EXPECT_EQ(map_addr & PAGE_MASK,
			    used_offset_for_size & PAGE_MASK,
			    "check returned address maintained offset");
		} else {
			T_QUIET; T_EXPECT_EQ(map_addr & PAGE_MASK, 0ull,
			    "check returned address is aligned");
		}

		r_addr = map_addr;
		kr = mach_vm_region(mach_task_self(), &r_addr, &r_size,
		    VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &icount,
		    &(mach_port_t){0});

		if (!should_fail) {
			want_addr = trunc_page(map_addr);
			if (mo_flags & (MAP_MEM_VM_COPY | MAP_MEM_VM_SHARE)) {
				/* mach_vm_map() only does full objects */
				want_size = round_page(mo_offset + mo_size) - trunc_page(mo_offset);
			} else {
				want_size = round_page(used_offset_for_size + map_size) - trunc_page(used_offset_for_size);
			}
			if (mo_flags & (MAP_MEM_VM_COPY | MAP_MEM_VM_SHARE)) {
				want_data = trunc_page(mo_offset) / sizeof(uint32_t);
			} else if (mo_flags & MAP_MEM_USE_DATA_ADDR) {
				want_data = (uint32_t)trunc_page(map_offset +
				    mo_offset) / sizeof(uint32_t);
			} else {
				want_data = (uint32_t)(trunc_page(map_offset) +
				    trunc_page(mo_offset)) / sizeof(uint32_t);
			}
			T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_vm_region(%p)", (void *)map_addr);
			T_QUIET; T_EXPECT_EQ(r_addr, want_addr, "validate region base");
			T_QUIET; T_EXPECT_EQ(r_size, want_size, "validate region size");
			for (uint32_t offs = 4; offs < r_size; offs += PAGE_SIZE) {
				T_QUIET; T_EXPECT_EQ(*(uint32_t *)(r_addr + offs),
				    want_data + (offs / 4),
				    "validate content at offset %d", offs);
			}
		}

		kr = mach_vm_deallocate(mach_task_self(), r_addr, r_size);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate(%p, %lld)", (void *)r_addr, r_size);
	}

	kr = mach_port_deallocate(mach_task_self(), mo_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "m_p_d(mo_port)");
}


T_DECL(mach_vm_map_unaligned,
    "check mach_vm_map() with misaligned offsets and sizes")
{
	kern_return_t kr;

	kr = mach_vm_map(mach_task_self(), &scratch_addr, scratch_size,
	    (64 << 10) - 1, VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, true,
	    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	T_EXPECT_MACH_SUCCESS(kr, "allocated scratch space: %p", (void *)scratch_addr);

	for (uint32_t i = 0; i < scratch_size / 4; i++) {
		((uint32_t *)scratch_addr)[i] = i;
	}

	for (struct mo_spec *mo = mo_specs; mo->s; mo++) {
		T_LOG("*** mo type: %s (return_data_addr == 0)", mo->s);
		for (struct range_spec *r = range_specs(); r->end; r++) {
			T_LOG("[%#llx, %#llx)", r->start, r->end);
			mach_vm_map_unaligned_test(mo->flags,
			    VM_FLAGS_ANYWHERE,
			    r->start, r->end - r->start);
		}
		T_LOG("");
	}

	for (struct mo_spec *mo = mo_specs; mo->s; mo++) {
		T_LOG("*** mo type: %s (return_data_addr == 1)", mo->s);
		for (struct range_spec *r = range_specs(); r->end; r++) {
			T_LOG("[%#llx, %#llx)", r->start, r->end);
			mach_vm_map_unaligned_test(mo->flags,
			    VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
			    r->start, r->end - r->start);
		}
		T_LOG("");
	}
}

T_DECL(vm_map_enter_mem_object_overflow,
    "Test overflow cases in vm_map_enter_mem_object",
    T_META_RUN_CONCURRENTLY(true), T_META_TAG_VM_PREFERRED)
{
	kern_return_t kr;

	mach_vm_address_t alloced_addr;
	mach_vm_size_t size_16kb, entry_size;
	vm_map_offset_t entry_offset;
	mach_port_t entry_handle;
	vm_map_offset_t target_addr, target_offset;
	int vmflags;

	size_16kb = 16 * 1024;
	/*
	 * Create an allocation in the source map, then get a non-page-aligned
	 * copy entry causing data_offset to be nonzero.
	 */
	kr = mach_vm_allocate(mach_task_self(), &alloced_addr, 2 * size_16kb, VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "set up allocation");

	entry_size = size_16kb;
	entry_offset = alloced_addr + (size_16kb / 2);
	kr = mach_make_memory_entry_64(mach_task_self(), &entry_size, entry_offset,
	    MAP_MEM_VM_COPY | MAP_MEM_USE_DATA_ADDR | VM_PROT_ALL,
	    &entry_handle, MACH_PORT_NULL);

	T_ASSERT_MACH_SUCCESS(kr, "set up copy memory entry");

	/*
	 * note: currently, the next three cases below are caught early by
	 * vm_map_enter_mem_object_sanitize and thus don't give any extra coverage
	 */

	/*
	 * In vm_map_enter_mem_object_sanitize, attempt to overflow obj_size by
	 * having size round up to 0.
	 */
	vmflags = VM_FLAGS_ANYWHERE;
	kr = mach_vm_map(mach_task_self(), &target_addr, (mach_vm_size_t) -1, 0,
	    vmflags, entry_handle, 0, true, VM_PROT_ALL, VM_PROT_ALL,
	    VM_INHERIT_DEFAULT);
	T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT, "obj_size overflow case");

	/*
	 * In vm_map_enter_adjust_offset, attempt to overflow obj_offs + quantity
	 * note: quantity = data_offset, which was set to a nonzero value
	 */
	vmflags = VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR;
	target_offset = (vm_map_offset_t) -1;
	kr = mach_vm_map(mach_task_self(), &target_addr, size_16kb, 0, vmflags,
	    entry_handle, target_offset, true, VM_PROT_ALL, VM_PROT_ALL,
	    VM_INHERIT_DEFAULT);
	T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT, "obj_offs overflow case");

	/*
	 * Attempt to overflow obj_end + quantity
	 */
	vmflags = VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR;
	target_offset = (vm_map_offset_t) -(size_16kb + 1);
	kr = mach_vm_map(mach_task_self(), &target_addr, size_16kb, 0, vmflags,
	    entry_handle, target_offset, true, VM_PROT_ALL, VM_PROT_ALL,
	    VM_INHERIT_DEFAULT);
	T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT, "obj_end overflow case");

	/*
	 * Because target_offset points to the second-to-last page and the
	 * size of the entry is one page (size_16kb), obj_end will point to the
	 * last page.
	 *
	 * In vm_map_enter_adjust_offset, this means obj_end + data_offset gets
	 * rounded up to 0
	 */
	target_offset = (vm_map_offset_t) -(2 * size_16kb);
	kr = mach_vm_map(mach_task_self(), &target_addr, size_16kb, 0, vmflags,
	    entry_handle, target_offset, true, VM_PROT_ALL, VM_PROT_ALL,
	    VM_INHERIT_DEFAULT);
	T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT, "round-to-0 case should be detected");
}
