#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <sys/sysctl.h>
#include <signal.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/port.h>
#include <pthread.h>
#include <dispatch/dispatch.h>
#include <sys/proc.h>
#include <sys/mman.h>

#define MAX_SENTINEL 4
#define countof(x) (sizeof(x) / sizeof(x[0]))

static bool
does_sentinel_match(char * start, char * end, char sentinel, char * desc)
{
	for (size_t i = 0; i < (end - start); i++) {
		if (start[i] != sentinel) {
			T_FAIL("%s doesn't match src[%zu] = %i != sentinel(%i)", desc, i, start[i], sentinel);
			return false;
		}
	}
	return true;
}

static bool
does_copy_match(char * dst, char * src, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (dst[i] != src[i]) {
			T_FAIL("dst(%i) != src(%i) at idx %lx/%zx", dst[i], src[i], i, len);
			return false;
		}
	}
	return true;
}

static char
get_random_char()
{
	char ret = rand();
	do {
		ret = rand();
	} while (ret <= MAX_SENTINEL);

	assert(ret > MAX_SENTINEL);
	return ret;
}

static bool
matches_src(char * src, size_t len, unsigned int seed)
{
	srand(seed);
	for (size_t i = 0; i < len; i++) {
		char value = get_random_char();
		if (src[i] != value) {
			T_FAIL("Src(%i) != %i", src[i], value);
			return false;
		}
	}
	return true;
}

static vm_object_id_t
get_object_id(mach_vm_address_t addr)
{
	mach_vm_size_t size;
	natural_t depth = 0;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
	vm_region_submap_info_data_64_t info;
	kern_return_t kr = mach_vm_region_recurse(mach_task_self(),
	    &addr,
	    &size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	assert(kr == KERN_SUCCESS);
	return info.object_id;
}

__attribute__((optnone))
static bool
test_one_copy_overwrite(vm_map_t map,
    mach_vm_address_t src_region_start,
    mach_vm_address_t src_region_end,
    mach_vm_address_t dst_region_start,
    mach_vm_address_t dst_region_end,
    mach_vm_address_t src_addr,
    mach_vm_address_t dst_addr,
    vm_map_address_t len,
    unsigned int seed,
    bool should_aligned_ids_match)
{
	kern_return_t kr;
	bool worked = true;

	assert(len <= src_region_end - src_region_start);
	assert(len <= dst_region_end - dst_region_start);
	assert(src_region_start <= src_addr);
	assert(dst_region_start <= dst_addr);

	char dst_overwritten_mem = 0;
	char src_before_sentinel = 1;
	char src_sentinel = 2;
	char src_after_sentinel = 3;
	char dst_sentinel = 4;

	assert(dst_sentinel <= MAX_SENTINEL);

	/* Setup dst, src with their sentinels */
	memset((char *)src_region_start, src_sentinel, src_region_end - src_region_start);
	memset((char *)src_region_start, src_before_sentinel, src_addr - src_region_start);
	memset((char *)src_addr + len, src_after_sentinel, src_region_end - (src_addr + len));
	memset((char *)dst_region_start, dst_sentinel, dst_region_end - dst_region_start);
	memset((char *)dst_addr, dst_overwritten_mem, len);

	/* Setup copy region with non-sentinel values */
	srand(seed);
	for (int i = 0; i < len; i++) {
		((char *)src_addr)[i] = (char) get_random_char();
	}

	vm_object_id_t object_before = get_object_id(dst_addr);

	kr = mach_vm_copy(mach_task_self(), src_addr, len, dst_addr);

	/*
	 * And verify everything looks good:
	 * 1) the dst matches the src
	 * 2) sentinels on either end are unchanged
	 * 3) the src is unchanged
	 */
	T_QUIET; T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "mach_vm_copy");
	worked &= does_copy_match((char *)dst_addr, (char *)src_addr, len);
	worked &= does_sentinel_match((char *)src_region_start, (char *)src_addr, src_before_sentinel, "src before");
	worked &= does_sentinel_match((char *)src_addr + len, (char *)src_region_end, src_after_sentinel, "src after");
	worked &= does_sentinel_match((char *)dst_region_start, (char *)dst_addr, dst_sentinel, "dst before");
	worked &= does_sentinel_match((char *)dst_addr + len, (char *)dst_region_end, dst_sentinel, "dst after");
	worked &= matches_src((char *)src_addr, len, seed);

	/* Verify the copy_overwrite did the proper thing with overwriting objects */
	bool aligned = (src_addr % PAGE_SIZE == 0) && (dst_addr % PAGE_SIZE == 0) && (len % PAGE_SIZE == 0);
	if (!should_aligned_ids_match) {
		/* The ids should never match, aligned or not */
		T_QUIET; T_ASSERT_NE(get_object_id(src_addr), get_object_id(dst_addr), "Object ids match when they should not");
	} else if (aligned) {
		/* aligned ids should match, and we're aligned */
		T_QUIET; T_ASSERT_EQ(get_object_id(src_addr), get_object_id(dst_addr), "Object ids of aligned copy match");
	} else {
		bool dst_addr_aligned = (dst_addr % PAGE_SIZE == 0);
		if (!dst_addr_aligned) {
			/* The dst wasn't aligned, so there's no way the id should have changed. */
			T_QUIET; T_ASSERT_EQ(object_before, get_object_id(dst_addr), "Object id was unchanged");
		}
	}

	return worked;
}

__enum_closed_decl(dst_mode_t, unsigned char, {
	DST_DEFAULT,
	DST_SHARED,
	DST_COPIED_SYMMETRIC,
	DST_MALLOC,
});

__enum_closed_decl(src_mode_t, unsigned char, {
	SRC_DEFAULT,
	SRC_EXTERNAL
});


static char tmppath[PATH_MAX] = "";
static int tmpfd;

static void
cleanup_tmpfile(void)
{
	if (tmppath[0] != '\0') {
		unlink(tmppath);
	}
	close(tmpfd);
	tmppath[0] = '\0';
}

static int
create_tmpfile(void)
{
	const char *tmpdir = dt_tmpdir();
	strlcat(tmppath, tmpdir ? tmpdir : "/tmp", sizeof(tmppath));
	strlcat(tmppath, "/xnu.vm_copy_overwrite.XXXXX", sizeof(tmppath));
	T_LOG("creating temporary file at %s", tmppath);
	int fd = mkstemp(tmppath);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "create temporary file");
	T_ATEND(cleanup_tmpfile);
	tmpfd = fd;
	return fd;
}


static mach_vm_address_t
setup_src_allocation(src_mode_t src_mode, size_t len)
{
	kern_return_t kr;
	switch (src_mode) {
	case SRC_DEFAULT:
		mach_vm_address_t src_start = 0;
		kr = mach_vm_allocate(mach_task_self(), &src_start, len, VM_FLAGS_ANYWHERE);
		assert(kr == KERN_SUCCESS);
		return src_start;
	case SRC_EXTERNAL:
		int fd = create_tmpfile();
		mach_vm_address_t temp = 0;
		kr = mach_vm_allocate(mach_task_self(), &temp, len, VM_FLAGS_ANYWHERE);
		assert(kr == KERN_SUCCESS);

		write(fd, (void *)temp, len);

		kr = mach_vm_deallocate(mach_task_self(), temp, len);
		assert(kr == KERN_SUCCESS);

		void * ptr = (void*)mmap(0, len, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fd, 0);
		assert(ptr != (void *)-1);

		return (mach_vm_address_t) ptr;
	}
}

static void
cleanup_src_allocation(src_mode_t src_mode, mach_vm_address_t addr, size_t len)
{
	kern_return_t kr = mach_vm_deallocate(mach_task_self(), addr, len);
	assert(kr == KERN_SUCCESS);

	if (src_mode == SRC_EXTERNAL) {
		cleanup_tmpfile();
	}
}

static mach_vm_address_t
setup_dst_allocation(dst_mode_t dst_mode, size_t len)
{
	mach_vm_address_t dst_start = 0;

	int dst_alloc_flags = VM_FLAGS_ANYWHERE;
	if (dst_mode == DST_MALLOC) {
		dst_alloc_flags |= VM_MAKE_TAG(VM_MEMORY_MALLOC_HUGE);
	}
	kern_return_t kr = mach_vm_allocate(mach_task_self(), &dst_start, len, dst_alloc_flags);
	assert(kr == KERN_SUCCESS);

	switch (dst_mode) {
	case DST_DEFAULT:
		break;
	case DST_MALLOC:
		break;
	case DST_SHARED:
		mach_vm_address_t remap_addr = 0;
		vm_prot_t cur_prot = VM_PROT_DEFAULT, max_prot = VM_PROT_DEFAULT;
		kr = mach_vm_remap(mach_task_self(), &remap_addr, len, 0,
		    VM_FLAGS_ANYWHERE, mach_task_self(), dst_start, false,
		    &cur_prot, &max_prot, VM_INHERIT_DEFAULT);
		assert(kr == KERN_SUCCESS);
	case DST_COPIED_SYMMETRIC:
		vm_offset_t out_addr;
		mach_msg_type_number_t out_size;
		kr = mach_vm_read(mach_task_self(), dst_start, len, &out_addr, &out_size);
		assert(kr == KERN_SUCCESS);
		kr = mach_vm_deallocate(mach_task_self(), out_addr, out_size);
		assert(kr == KERN_SUCCESS);
	}
	return dst_start;
}

static void
cleanup_dst_allocation(dst_mode_t dst_mode, mach_vm_address_t addr, size_t len)
{
	kern_return_t kr = mach_vm_deallocate(mach_task_self(), addr, len);
	assert(kr == KERN_SUCCESS);
}


static void __attribute__((optnone))
mach_vm_copy_tests(dst_mode_t dst_mode, src_mode_t src_mode)
{
	time_t seed = time(NULL);
	T_LOG("Running with initial seed %lu", seed);

	mach_vm_address_t src_start = 0, dst_start = 0;
	mach_vm_size_t len      = (32 * 1024) * 5;
	mach_vm_size_t copy_len = (32 * 1024) * 3; /* Big enough to avoid msg_ool_size */

	src_start = setup_src_allocation(src_mode, len);
	dst_start = setup_dst_allocation(dst_mode, len);

	int src_offsets[] = {0, -1, 1, 0x4000};
	int len_offsets[] = {0, -1, 1, 0x4000};
	int dst_offsets[] = {0, -1, 1};

	for (int i = 0; i < countof(src_offsets); i++) {
		for (int j = 0; j < countof(dst_offsets); j++) {
			for (int k = 0; k < countof(len_offsets); k++) {
				vm_map_address_t src_start_adjusted = src_start + 32 * 1024;
				vm_map_address_t dst_start_adjusted = dst_start + 32 * 1024;

				assert(copy_len <= len - (32 * 1024) * 2);

				memset((char *)src_start, 0, len);
				memset((char *)dst_start, 0, len);

				bool should_aligned_ids_match = true;
				if (dst_mode == DST_SHARED) {
					should_aligned_ids_match = false;
				}
				if (dst_mode == DST_MALLOC && src_mode == SRC_EXTERNAL) {
					should_aligned_ids_match = false;
				}

				bool worked = test_one_copy_overwrite(mach_task_self(),
				    src_start, src_start + len,
				    dst_start, dst_start + len,
				    src_start_adjusted + src_offsets[i],
				    dst_start_adjusted + dst_offsets[j],
				    copy_len + len_offsets[k], seed,
				    should_aligned_ids_match);

				T_QUIET; T_ASSERT_EQ_INT(worked, true,
				    "Copy Overwrite(mode = %i) src + %i, dst + %i, len + %i len=%llx",
				    dst_mode,
				    src_offsets[i], dst_offsets[j], len_offsets[k],
				    copy_len + len_offsets[k]);

				seed++;
			}
		}
	}

	cleanup_src_allocation(src_mode, src_start, len);
	cleanup_dst_allocation(dst_mode, dst_start, len);

	T_PASS("Copy overwrite test pass");
}

T_DECL(copy_overwrite_correctness, "copy overwrite different alignments")
{
	/*
	 * Each of these configurations tests a possibly different setup
	 * of src/dst memory config that could result in different behavior
	 * by copy_overwrite. Many of these also change whether copy_overwrite
	 * will take the optimized path of transferring objects or do a physical
	 * copy.
	 */
	mach_vm_copy_tests(DST_DEFAULT, SRC_DEFAULT);
	mach_vm_copy_tests(DST_SHARED, SRC_DEFAULT);
	mach_vm_copy_tests(DST_COPIED_SYMMETRIC, SRC_DEFAULT);
	mach_vm_copy_tests(DST_DEFAULT, SRC_EXTERNAL);
	mach_vm_copy_tests(DST_MALLOC, SRC_EXTERNAL);
}
