#include <darwintest.h>
#include <darwintest_utils.h>

#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/task_info.h>
#include <mach/vm_param.h>
#include <mach/vm_types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <TargetConditionals.h>

enum {
	DEFAULT = 0,
	HEAP,
	LARGE_FILE
};

static char _filepath[MAXPATHLEN];
static struct mach_vm_range parent_default;
static struct mach_vm_range parent_heap;

#define CHILD_PROCESS_COUNT     (20)
#undef KiB
#undef MiB
#undef GiB
#define KiB(x)  ((uint64_t)(x) << 10)
#define MiB(x)  ((uint64_t)(x) << 20)
#define GiB(x)  ((uint64_t)(x) << 30)

#define ALLOCATION_SIZE (PAGE_SIZE)
#define LARGE_ALLOCATION_SIZE (GiB(1))
#define PER_ALLOC_AMT_GB (GiB(256))
#define N_ALLOC 5


/*
 * Choose an arbitrary memory tag which applies to each of default/heap range
 * for testing placement of allocations.
 */
#define VM_MEMORY_RANGE_DEFAULT (VM_MAKE_TAG(VM_MEMORY_STACK))
#define VM_MEMORY_RANGE_HEAP    (VM_MAKE_TAG(VM_MEMORY_MALLOC_SMALL))

#define RANGE_DEFAULT_FLAGS     (VM_FLAGS_ANYWHERE | VM_MEMORY_RANGE_DEFAULT)
#define RANGE_HEAP_FLAGS        (VM_FLAGS_ANYWHERE | VM_MEMORY_RANGE_HEAP)

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_ENABLED(!TARGET_OS_OSX),
	T_META_OWNER("mmorran")
	);

static bool
ranges_enabled(void)
{
	struct mach_vm_range range;
	size_t range_sz = sizeof(range);

	bzero(&range, sizeof(range));

	/*
	 * We will fail with ENOENT or EINVAL if ranges are either not supported
	 * or not enabled on our process.
	 */
	return sysctlbyname("vm.vm_map_user_range_default",
	           &range, &range_sz, NULL, 0) == 0;
}

#define CHECK_RANGES_ENABLED() \
	if (!ranges_enabled()) { \
	        T_SKIP("VM map ranges not enabled"); \
	}

static struct mach_vm_range
get_range(int target_range)
{
	int ret = EINVAL;
	struct mach_vm_range range;
	size_t range_sz = sizeof(range);

	bzero(&range, sizeof(range));

	switch (target_range) {
	case DEFAULT:
		ret = sysctlbyname("vm.vm_map_user_range_default", &range, &range_sz, NULL, 0);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(ret, "successfully retrieved user default range");
		break;

	case HEAP:
		ret = sysctlbyname("vm.vm_map_user_range_heap", &range, &range_sz, NULL, 0);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(ret, "successfully retrieved user heap range");
		break;

	case LARGE_FILE:
		ret = sysctlbyname("vm.vm_map_user_range_large_file", &range, &range_sz, NULL, 0);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(ret, "successfully retrieved user large file range");
		break;

	default:
		/* Fall through with EINVAL */
		break;
	}

	return range;
}

static task_vm_info_data_t
get_vm_task_info(void)
{
	task_vm_info_data_t ti;

	mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
	kern_return_t const kr = task_info(mach_task_self(),
	    TASK_VM_INFO,
	    (task_info_t) &ti,
	    &count);
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(kr, "get task_info()");
	return ti;
}

static mach_vm_address_t
assert_allocate(mach_vm_address_t dst, int vm_flags)
{
	int ret = mach_vm_allocate(mach_task_self(), &dst, ALLOCATION_SIZE, vm_flags);
	T_ASSERT_MACH_SUCCESS(ret, "vm_allocate");
	return dst;
}

static void
assert_in_range(struct mach_vm_range range, mach_vm_offset_t addr)
{
	T_LOG("checking if %llx <= %llx <= %llx", range.min_address, addr,
	    range.max_address);
	T_EXPECT_GE(addr, range.min_address, "allocation above min address");
	T_EXPECT_LE(addr, range.max_address, "allocation below max address");
}

static void
assert_in_heap_range(mach_vm_offset_t addr)
{
	struct mach_vm_range range = get_range(HEAP);

	assert_in_range(range, addr);
}

static void *
assert_mmap(void *addr, size_t sz, int fd, int flags)
{
	void *ret = mmap(addr, sz, VM_PROT_READ | VM_PROT_WRITE,
	    flags, fd, 0);
	T_EXPECT_NE(ret, MAP_FAILED, "mmap should not have MAP_FAILED");
	T_EXPECT_NE(ret, NULL, "mmap should have returned a valid pointer");
	return ret;
}

static void
assert_allocate_eq(mach_vm_address_t dst, int vm_flags)
{
	mach_vm_address_t target = dst;

	T_ASSERT_MACH_SUCCESS(mach_vm_allocate(mach_task_self(), &target,
	    ALLOCATION_SIZE, vm_flags), "vm_allocate");

	T_EXPECT_EQ(target, dst, "target/dst differ");
}

static mach_vm_address_t
assert_allocate_in_range(int target_range, mach_vm_address_t dst, int vm_flags)
{
	struct mach_vm_range range = get_range(target_range);
	dst = assert_allocate(dst, vm_flags);

	assert_in_range(range, (mach_vm_offset_t)dst);

	return dst;
}

static void *
assert_mmap_in_range(void *addr, int target_range, size_t sz, int fd, int flags)
{
	struct mach_vm_range range = get_range(target_range);
	void *dst = assert_mmap(addr, sz, fd, flags);

	assert_in_range(range, (mach_vm_offset_t)dst);

	return dst;
}

static void
ensure_mmap_fails(void *addr, size_t sz, int flags, int fd)
{
	void *ret = mmap(addr, sz, VM_PROT_READ | VM_PROT_WRITE, flags, fd, 0);
	T_QUIET;
	T_EXPECT_EQ_PTR(ret, MAP_FAILED, "mmap should fail");
}

__attribute__((overloadable))
static void
fork_child_test(void (^child_test)(void))
{
	pid_t child_pid;
	int err;

	child_pid = fork();

	if (child_pid == 0) {
		/* child process */
		T_LOG("in child");
		child_test();
		exit(0);
	} else {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(child_pid, "fork process");

		/* wait for child process to exit */
		if (dt_waitpid(child_pid, &err, NULL, 30) == false) {
			T_FAIL("dt_waitpid() failed on child pid %d", child_pid);
		}
	}
}

__attribute__((overloadable))
static void
fork_child_test(void (*child_test)(void))
{
	fork_child_test(^{
		child_test();
	});
}

static void
cleanup_file(void)
{
	unlink(_filepath);
	bzero(_filepath, MAXPATHLEN);
}

T_DECL(range_allocate_heap,
    "ensure malloc tagged memory is allocated within the heap range", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	assert_allocate_in_range(HEAP, 0, RANGE_HEAP_FLAGS);
}

T_DECL(range_allocate_anywhere,
    "ensure allocation is within target range when hint is outwith range", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	struct mach_vm_range range = get_range(HEAP);

	assert_allocate_in_range(HEAP, range.min_address - ALLOCATION_SIZE, RANGE_HEAP_FLAGS);
}

T_DECL(range_allocate_stack,
    "ensure a stack allocation is in the default range", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	assert_allocate_in_range(DEFAULT, 0, RANGE_DEFAULT_FLAGS);
}

static void
ensure_fixed_mappings_succeed_cross(int heap)
{
	vm_map_address_t addr;

	addr = assert_allocate(0, VM_FLAGS_ANYWHERE | heap);
	vm_deallocate(mach_task_self(), addr, ALLOCATION_SIZE);

	assert_allocate_eq(addr, VM_FLAGS_FIXED | VM_MEMORY_RANGE_DEFAULT);
	assert_allocate_eq(addr, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MEMORY_RANGE_DEFAULT);
	vm_deallocate(mach_task_self(), addr, ALLOCATION_SIZE);

	assert_allocate_eq(addr, VM_FLAGS_FIXED | VM_MEMORY_RANGE_HEAP);
	assert_allocate_eq(addr, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MEMORY_RANGE_HEAP);
	vm_deallocate(mach_task_self(), addr, ALLOCATION_SIZE);
}

static void
ensure_rogue_fixed_fails(void)
{
	struct mach_vm_range def = get_range(DEFAULT);
	struct mach_vm_range heap = get_range(HEAP);
	mach_vm_address_t addr;
	kern_return_t kr;

	if (def.max_address + 3 * ALLOCATION_SIZE <= heap.min_address) {
		addr = heap.min_address - 2 * ALLOCATION_SIZE;
	} else {
		/*
		 * in the unlikely event when there's no space
		 * between default and heap, then there must be
		 * a hole after heap.
		 */
		addr = heap.max_address + ALLOCATION_SIZE;
	}

	kr = mach_vm_allocate(mach_task_self(), &addr,
	    ALLOCATION_SIZE, VM_FLAGS_FIXED);
	T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ADDRESS, "should fail");
}

static void
ensure_fixed_mapping(void)
{
	ensure_fixed_mappings_succeed_cross(VM_MEMORY_RANGE_DEFAULT);
	ensure_fixed_mappings_succeed_cross(VM_MEMORY_RANGE_HEAP);

	ensure_rogue_fixed_fails();
}

T_DECL(range_allocate_fixed, "ensure fixed target is honored (even with an incorrect tag)", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	ensure_fixed_mapping();
	fork_child_test(ensure_fixed_mapping);
}

T_DECL(range_mmap_anon, "ensure anon mapping within HEAP range", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	assert_mmap_in_range(NULL, HEAP, ALLOCATION_SIZE, -1, MAP_ANON | MAP_PRIVATE);
}

T_DECL(range_mmap_file, "ensure file is mapped within HEAP range", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	int fd = -1;

	/* prepare temp file */
	strncpy(_filepath, "/tmp/mapfile.XXXXXX", MAXPATHLEN);
	T_ASSERT_POSIX_SUCCESS(fd = mkstemp(_filepath), NULL);
	atexit(cleanup_file);

	T_ASSERT_POSIX_SUCCESS(ftruncate(fd, (off_t)ALLOCATION_SIZE), NULL);

	/* map it in to the heap rage */
#if TARGET_OS_OSX
	T_LOG("mapping file in DEFAULT range");
	assert_mmap_in_range(NULL, DEFAULT, ALLOCATION_SIZE, fd, MAP_FILE | MAP_SHARED);
#else
	T_LOG("mapping file in HEAP range");
	assert_mmap_in_range(NULL, HEAP, ALLOCATION_SIZE, fd, MAP_FILE | MAP_SHARED);
#endif
}


T_DECL(range_mmap_alias_tag, "ensure anon mapping with tag is honored", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	assert_mmap_in_range(NULL, DEFAULT, ALLOCATION_SIZE, VM_MEMORY_RANGE_DEFAULT, MAP_ANON | MAP_PRIVATE);
}

T_DECL(range_mmap_with_low_hint,
    "ensure allocation is within target range when hint is below range", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	struct mach_vm_range range = get_range(HEAP);
	mach_vm_address_t target = range.min_address - ALLOCATION_SIZE;

	assert_mmap_in_range((void *)target, HEAP, ALLOCATION_SIZE, -1, MAP_ANON | MAP_PRIVATE);
}

T_DECL(range_mmap_with_high_hint,
    "ensure allocation is within target range when hint is within range", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	struct mach_vm_range range = get_range(HEAP);
	mach_vm_address_t target = range.max_address - 100 * ALLOCATION_SIZE;

	void *dst = assert_mmap_in_range((void *)target, HEAP, ALLOCATION_SIZE, -1, MAP_ANON | MAP_PRIVATE);

	T_EXPECT_EQ((mach_vm_address_t)dst, target, "unexpected allocation address");
}

T_DECL(range_mmap_with_bad_hint,
    "ensure allocation fails when hint is above range", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	struct mach_vm_range range = get_range(HEAP);
	mach_vm_address_t target = range.max_address + 0x100000000;

	/* mmap should retry with 0 base on initial KERN_NO_SPACE failure */
	assert_mmap_in_range((void *)target, HEAP, ALLOCATION_SIZE, -1, MAP_ANON | MAP_PRIVATE);
}

T_DECL(range_mach_vm_map_with_bad_hint,
    "ensure mach_vm_map fails when hint is above range", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	struct mach_vm_range range = get_range(HEAP);
	mach_vm_address_t addr = range.max_address + 0x100000000;

	/*
	 * unlike mmap & vm_allocate, mach_vm_map should fail when given a hint
	 * out with the target range.
	 */
	int ret = mach_vm_map(mach_task_self(), &addr, ALLOCATION_SIZE,
	    (mach_vm_offset_t)0, VM_FLAGS_ANYWHERE, MACH_PORT_NULL,
	    (memory_object_offset_t)0, FALSE, VM_PROT_DEFAULT, VM_PROT_ALL,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_EXPECT_EQ(ret, KERN_NO_SPACE, "expected KERN_NO_SPACE");
}

T_DECL(range_mach_vm_remap_default,
    "ensure mach_vm_remap is successful in default range", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	vm_prot_t curprot;
	vm_prot_t maxprot;

	mach_vm_address_t addr = assert_allocate_in_range(DEFAULT, 0, RANGE_DEFAULT_FLAGS);
	mach_vm_address_t target = addr + ALLOCATION_SIZE;

	int ret = mach_vm_remap(mach_task_self(), &target, ALLOCATION_SIZE,
	    (mach_vm_offset_t)0, VM_FLAGS_ANYWHERE, mach_task_self(),
	    addr, FALSE, &curprot, &maxprot, VM_INHERIT_NONE);
	T_QUIET; T_EXPECT_EQ(ret, KERN_SUCCESS, "expected KERN_SUCCESS");
}

T_DECL(range_mach_vm_remap_heap_with_hint,
    "ensure mach_vm_remap is successful in heap range", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	vm_prot_t curprot;
	vm_prot_t maxprot;

	mach_vm_address_t addr = assert_allocate_in_range(HEAP, 0, RANGE_HEAP_FLAGS);
	mach_vm_address_t target = addr + ALLOCATION_SIZE;

	int ret = mach_vm_remap(mach_task_self(), &target, ALLOCATION_SIZE,
	    (mach_vm_offset_t)0, VM_FLAGS_ANYWHERE, mach_task_self(),
	    addr, FALSE, &curprot, &maxprot, VM_INHERIT_NONE);
	T_QUIET; T_EXPECT_EQ(ret, KERN_SUCCESS, "expected KERN_SUCCESS");
	assert_in_heap_range(target);
}

T_DECL(range_mach_vm_remap_heap,
    "ensure mach_vm_remap remains in same range", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	vm_prot_t curprot;
	vm_prot_t maxprot;

	mach_vm_address_t addr = assert_allocate_in_range(HEAP, 0, RANGE_HEAP_FLAGS);
	mach_vm_address_t target = 0;

	int ret = mach_vm_remap(mach_task_self(), &target, ALLOCATION_SIZE,
	    (mach_vm_offset_t)0, VM_FLAGS_ANYWHERE, mach_task_self(),
	    addr, FALSE, &curprot, &maxprot, VM_INHERIT_NONE);
	T_EXPECT_EQ(ret, KERN_SUCCESS, "expected KERN_SUCCESS");
	assert_in_heap_range(target);
}

static void
ensure_range(void)
{
	struct mach_vm_range def = get_range(DEFAULT);
	struct mach_vm_range heap = get_range(HEAP);

	T_EXPECT_GT(heap.min_address, def.max_address,
	    "ranges should not overlap");
	T_EXPECT_LE(heap.max_address, MACH_VM_MAX_ADDRESS,
	    "expected max <= %llx", MACH_VM_MAX_ADDRESS);
	T_EXPECT_EQ(heap.min_address,
	    heap.min_address & (unsigned long)~0x1FFFFF,
	    "expected alignment on 2MB TT boundary");
}

static void
ensure_child_range(void)
{
	struct mach_vm_range def = get_range(DEFAULT);
	struct mach_vm_range heap = get_range(HEAP);

	T_QUIET; T_EXPECT_EQ(def.min_address, parent_default.min_address,
	    "expected forked default min to be equal");
	T_QUIET; T_EXPECT_EQ(def.max_address, parent_default.max_address,
	    "expected forked default max to be equal");
	T_QUIET; T_EXPECT_EQ(heap.min_address, parent_heap.min_address,
	    "expected forked heap min to be equal");
	T_QUIET; T_EXPECT_EQ(heap.max_address, parent_heap.max_address,
	    "expected forked heap max to be equal");
}

T_DECL(range_ensure_bounds, "ensure ranges respect map bounds", T_META_TAG_VM_PREFERRED)
{
	CHECK_RANGES_ENABLED();

	parent_default = get_range(DEFAULT);
	parent_heap = get_range(HEAP);

	ensure_range();

	for (uint32_t i = 0; i < CHILD_PROCESS_COUNT; i++) {
		fork_child_test(ensure_child_range);
	}
}

static bool
parse_void_ranges(struct mach_vm_range *void1, struct mach_vm_range *void2)
{
	char buf[256];
	size_t bsz = sizeof(buf) - 1;
	char *s;

	if (sysctlbyname("vm.malloc_ranges", buf, &bsz, NULL, 0) == -1) {
		if (errno == ENOENT) {
			return false;
		}
		T_ASSERT_POSIX_SUCCESS(-1, "sysctlbyname(vm.malloc_ranges)");
	}
	buf[bsz] = '\0';

	s = buf;

	void1->min_address = strtoull(s, &s, 16);
	T_QUIET; T_ASSERT_EQ(*s, ':', "should have a ':'");
	s++;

	void1->max_address = strtoull(s, &s, 16);
	T_QUIET; T_ASSERT_EQ(*s, ' ', "should have a ' '");
	s++;

	void2->min_address = strtoull(s, &s, 16);
	T_QUIET; T_ASSERT_EQ(*s, ':', "should have a ':'");
	s++;

	void2->max_address = strtoull(s, &s, 16);
	T_QUIET; T_ASSERT_EQ(*s, '\0', "should be done");

	return true;
}

T_DECL(create_range, "ensure create ranges kinda works", T_META_TAG_VM_PREFERRED)
{
	struct mach_vm_range void1, void2, *r;

	mach_vm_range_recipe_v1_t array[10];
	uint32_t nranges = 0;

	if (!parse_void_ranges(&void1, &void2)) {
		T_SKIP("malloc_ranges not supported");
	}

	T_LOG("Ranges are %#llx:%#llx %#llx:%#llx",
	    void1.min_address, void1.max_address,
	    void2.min_address, void2.max_address);

#define reset() \
	nranges = 0
#define add_range(l, r) \
	array[nranges++] = (mach_vm_range_recipe_v1_t){ \
	    .range = { l, r }, .range_tag = MACH_VM_RANGE_FIXED, \
	}
#define create_ranges() \
	mach_vm_range_create(mach_task_self(), MACH_VM_RANGE_FLAVOR_V1, \
	    (mach_vm_range_recipes_raw_t)array, sizeof(array[0]) * nranges)

	if (void1.min_address + MiB(128) > void1.max_address) {
		r = &void2;
	} else {
		r = &void1;
	}

	reset();
	add_range(void1.min_address - MiB(10), void1.min_address);
	T_EXPECT_MACH_ERROR(create_ranges(), KERN_INVALID_ARGUMENT,
	    "should fail: range outside of voids");

	reset();
	add_range(r->min_address + MiB(1), r->min_address + MiB(3));
	add_range(r->min_address, r->min_address + MiB(2));
	T_EXPECT_MACH_ERROR(create_ranges(), KERN_INVALID_ARGUMENT,
	    "should fail: overlapping ranges");

	reset();
	add_range(r->min_address, r->min_address + MiB(1));
	add_range(r->min_address + MiB(2), r->min_address + MiB(3));
	T_EXPECT_MACH_SUCCESS(create_ranges(), "should succeed");

	reset();
	add_range(r->min_address, r->min_address + MiB(1));
	add_range(r->min_address + MiB(2), r->min_address + MiB(3));
	T_EXPECT_MACH_ERROR(create_ranges(), KERN_MEMORY_PRESENT,
	    "should fail: already allocated");

	reset();
	add_range(r->min_address + MiB(4), r->min_address + MiB(5));
	add_range(r->min_address + MiB(6), r->min_address + MiB(7));
	T_EXPECT_MACH_SUCCESS(create_ranges(), "should succeed");

	__block vm_offset_t offs = 0;

	void (^check_works)(void) = ^{
		mach_vm_address_t addr;
		kern_return_t kr;

		offs += PAGE_SIZE;
		addr  = r->min_address + offs;
		assert_allocate_eq(addr, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);

		addr  = r->min_address + MiB(2) + offs;
		assert_allocate_eq(addr, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);

		addr  = r->min_address + MiB(1);
		kr = mach_vm_allocate(mach_task_self(), &addr, ALLOCATION_SIZE,
		    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
		T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ADDRESS, "should fail");
	};

	check_works();
	fork_child_test(check_works);

#undef create_ranges
#undef add_range
#undef reset
}

T_DECL(range_mmap_too_large, "ensure mmap fails when allocation is too large", T_META_TAG_VM_PREFERRED)
{
	// Get VM map min_offset and max_offset
	task_vm_info_data_t const ti = get_vm_task_info();
	T_LOG("task_info range: 0x%llx-0x%llx, covering %llu bytes of memory",
	    ti.min_address, ti.max_address, ti.max_address - ti.min_address);

	// Try to mmap more memory than the address space can handle
	size_t const sz_too_large = ti.max_address - ti.min_address + 1;
	T_LOG("Trying to allocate %zu bytes", sz_too_large);
	ensure_mmap_fails(NULL, sz_too_large, MAP_ANON | MAP_PRIVATE, -1);
}

T_DECL(range_mmap_outside_map_range_fixed,
    "ensure mmap fails when making a fixed allocation beyond VM map max address", T_META_TAG_VM_PREFERRED)
{
	// Get VM map min_offset and max_offset
	task_vm_info_data_t const ti = get_vm_task_info();
	T_LOG("task_info range: 0x%llx-0x%llx", ti.min_address, ti.max_address);

	// Try to allocate a page between VM map max_offset and MACH_VM_MAX_ADDRESS
	mach_vm_address_t const target = ti.max_address + PAGE_SIZE;
	T_LOG("Trying to allocate memory at 0x%llx", target);
	ensure_mmap_fails((void *)target, ALLOCATION_SIZE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1);
}

static bool
large_file_range_enabled(void)
{
	struct mach_vm_range range;
	size_t range_sz = sizeof(range);

	bzero(&range, sizeof(range));

	/*
	 * We will fail with ENOENT or EINVAL if ranges are either not supported
	 * or not enabled on our process.
	 */
	int const ret = sysctlbyname("vm.vm_map_user_range_large_file",
	    &range, &range_sz, NULL, 0);
	if (ret) {
		T_LOG("vm.vm_map_user_range_large_file errno: %d", errno);
	} else {
		T_LOG("large file range: (%llx, %llx)",
		    range.min_address, range.max_address);
	}
	return ret == 0;
}

T_DECL(range_mmap_large_file,
    "ensure large file is mapped within LARGE_FILE range", T_META_TAG_VM_PREFERRED)
{
	if (!large_file_range_enabled()) {
		T_SKIP("large file range not enabled");
	}

	void *ptrs[N_ALLOC];
	uint32_t i;

	int fd = -1;
	/* prepare temp file */
	char const * tmp_dir = dt_tmpdir();
	snprintf(_filepath, MAXPATHLEN, "%s/maplargefile.XXXXXX", tmp_dir);
	T_ASSERT_POSIX_SUCCESS(fd = mkstemp(_filepath), NULL);
	atexit(cleanup_file);

	T_LOG("Attempting to allocate VA space in %llu GB chunks.",
	    LARGE_ALLOCATION_SIZE);
	for (i = 0; i < N_ALLOC; ++i) {
		void *p = assert_mmap_in_range(NULL, LARGE_FILE, LARGE_ALLOCATION_SIZE,
		    fd, MAP_SHARED | MAP_FILE);
		if (p == MAP_FAILED) {
			if (errno != ENOMEM) {
				T_WITH_ERRNO;
				T_LOG("mmap failed: stopped at %u of %d/%llu GB chunks",
				    i + 1, N_ALLOC, LARGE_ALLOCATION_SIZE);
			}
			break;
		} else {
			T_LOG("allocation %u: %p", i + 1, p);
		}

		T_QUIET; T_ASSERT_NOTNULL(p, "mmap");
		ptrs[i] = p;
	}

	T_EXPECT_GE_UINT(i, N_ALLOC, "Allocate at least %u/%d %llu-GB chunks of VA space",
	    i, N_ALLOC, (LARGE_ALLOCATION_SIZE / GiB(1)));

	T_LOG("Unmapping memory");
	for (uint32_t j = 0; j < i; ++j) {
		int const res = munmap(ptrs[j], LARGE_ALLOCATION_SIZE);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(res, 0, "munmap");
	}
}
