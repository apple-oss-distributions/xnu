#include <darwintest.h>
#include <darwintest_utils.h>

#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <TargetConditionals.h>

typedef void (*child_test)(void);

enum {
	DEFAULT = 0,
	HEAP
};

static vm_size_t _allocation_size = 0;
static char _filepath[MAXPATHLEN];
static struct mach_vm_range parent_default;
static struct mach_vm_range parent_heap;

#define CHILD_PROCESS_COUNT     (20)
#define MAX_VM_ADDRESS          (0xFC0000000ULL)

/*
 * Choose an arbitrary memory tag which applies to each of default/heap range
 * for testing placement of allocations.
 */
#define VM_MEMORY_RANGE_DEFAULT (VM_MAKE_TAG(VM_MEMORY_STACK))
#define VM_MEMORY_RANGE_HEAP    (VM_MAKE_TAG(VM_MEMORY_MALLOC))

#define RANGE_DEFAULT_FLAGS     (VM_FLAGS_ANYWHERE | VM_MEMORY_RANGE_DEFAULT)
#define RANGE_HEAP_FLAGS        (VM_FLAGS_ANYWHERE | VM_MEMORY_RANGE_HEAP)

#define TARGET_OS_OTHER 0

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_ENABLED(TARGET_OS_IOS || TARGET_OS_OTHER),
	T_META_OWNER("mmorran")
	);

static void
set_allocation_size(size_t sz)
{
	_allocation_size = sz;
}

static bool
ranges_enabled()
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

static void
do_test(void (^test)(void))
{
	if (!ranges_enabled()) {
		T_SKIP("VM map ranges not enabled");
	}

	test();
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

	default:
		/* Fall through with EINVAL */
		break;
	}

	return range;
}

static mach_vm_address_t
assert_allocate(mach_vm_address_t dst, int vm_flags)
{
	int ret = mach_vm_allocate(mach_task_self(), &dst, _allocation_size, vm_flags);
	T_ASSERT_MACH_SUCCESS(ret, "vm_allocate");
	return dst;
}

static void
assert_in_range(struct mach_vm_range range, mach_vm_offset_t addr)
{
	T_LOG("checking if %llx <= %llx <= %llx", range.min_address, addr,
	    range.max_address);
	T_EXPECT_GE(addr, range.min_address, "allocation above heap min address");
	T_EXPECT_LE(addr, range.max_address, "allocation below heap max address");
}

static void
assert_in_heap_range(mach_vm_offset_t addr)
{
	struct mach_vm_range range = get_range(HEAP);

	assert_in_range(range, addr);
}

static void *
assert_mmap(void *addr, int fd, int flags)
{
	void *ret = mmap(addr, _allocation_size, VM_PROT_READ | VM_PROT_WRITE,
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
	    _allocation_size, vm_flags), "vm_allocate");

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
assert_mmap_in_range(void *addr, int target_range, int fd, int flags)
{
	struct mach_vm_range range = get_range(target_range);
	void *dst = assert_mmap(addr, fd, flags);

	assert_in_range(range, (mach_vm_offset_t)dst);

	return dst;
}

static void
fork_child_test(child_test func)
{
	pid_t child_pid;
	int err;

	child_pid = fork();

	if (child_pid == 0) {
		/* child process */
		func();
		exit(0);
	} else {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(child_pid, "fork process");

		/* wait for child process to exit */
		if (dt_waitpid(child_pid, &err, NULL, 30) == false) {
			T_FAIL("dt_waitpid() failed on child pid %d", child_pid);
		}
	}
}

static void
cleanup_file(void)
{
	unlink(_filepath);
	bzero(_filepath, MAXPATHLEN);
}

T_DECL(range_allocate_heap,
    "ensure malloc tagged memory is allocated within the heap range")
{
	do_test(^{
		set_allocation_size(PAGE_SIZE);
		assert_allocate_in_range(HEAP, 0, RANGE_HEAP_FLAGS);
	});
}

T_DECL(range_allocate_anywhere,
    "ensure allocation is within target range when hint is outwith range")
{
	do_test(^{
		struct mach_vm_range range = get_range(HEAP);

		set_allocation_size(PAGE_SIZE);
		assert_allocate_in_range(HEAP, range.min_address - _allocation_size, RANGE_HEAP_FLAGS);
	});
}

T_DECL(range_allocate_stack,
    "ensure a stack allocation is in the default range")
{
	do_test(^{
		set_allocation_size(PAGE_SIZE);
		assert_allocate_in_range(DEFAULT, 0, RANGE_DEFAULT_FLAGS);
	});
}

T_DECL(range_allocate_fixed, "ensure fixed target is honored")
{
	do_test(^{
		struct mach_vm_range range = get_range(HEAP);

		set_allocation_size(PAGE_SIZE);
		assert_allocate_eq(range.min_address - _allocation_size, VM_FLAGS_FIXED | VM_MEMORY_RANGE_HEAP);
	});
}

T_DECL(range_mmap_anon, "ensure anon mapping within HEAP range")
{
	do_test(^{
		set_allocation_size(PAGE_SIZE);

		assert_mmap_in_range(NULL, HEAP, -1, MAP_ANON | MAP_PRIVATE);
	});
}

T_DECL(range_mmap_file, "ensure file is mapped within HEAP range")
{
	do_test(^{
		int fd = -1;

		set_allocation_size(PAGE_SIZE);

		/* prepare temp file */
		strncpy(_filepath, "/tmp/mapfile.XXXXXX", MAXPATHLEN);
		T_ASSERT_POSIX_SUCCESS(fd = mkstemp(_filepath), NULL);
		atexit(cleanup_file);

		T_ASSERT_POSIX_SUCCESS(ftruncate(fd, (off_t)_allocation_size), NULL);

		/* map it in to the heap rage */
		T_LOG("mapping file in HEAP range");
		assert_mmap_in_range(NULL, HEAP, fd, MAP_FILE | MAP_SHARED);
	});
}


T_DECL(range_mmap_alias_tag, "ensure anon mapping with tag is honored")
{
	do_test(^{
		set_allocation_size(PAGE_SIZE);
		assert_mmap_in_range(NULL, DEFAULT, VM_MEMORY_RANGE_DEFAULT, MAP_ANON | MAP_PRIVATE);
	});
}

T_DECL(range_mmap_with_low_hint,
    "ensure allocation is within target range when hint is below range")
{
	do_test(^{
		struct mach_vm_range range = get_range(HEAP);
		mach_vm_address_t target = range.min_address - _allocation_size;

		set_allocation_size(PAGE_SIZE);
		assert_mmap_in_range((void *)target, HEAP, -1, MAP_ANON | MAP_PRIVATE);
	});
}

T_DECL(range_mmap_with_high_hint,
    "ensure allocation is within target range when hint is within range")
{
	do_test(^{
		struct mach_vm_range range = get_range(HEAP);
		mach_vm_address_t target = range.min_address + 0x100000000;

		set_allocation_size(PAGE_SIZE);
		void *dst = assert_mmap_in_range((void *)target, HEAP, -1, MAP_ANON | MAP_PRIVATE);

		T_EXPECT_EQ((mach_vm_address_t)dst, target, "unexpected allocation address");
	});
}

T_DECL(range_mmap_with_bad_hint,
    "ensure allocation fails when hint is above range")
{
	do_test(^{
		struct mach_vm_range range = get_range(HEAP);
		mach_vm_address_t target = range.max_address + 0x100000000;

		set_allocation_size(PAGE_SIZE);

		/* mmap should retry with 0 base on initial KERN_NO_SPACE failure */
		assert_mmap_in_range((void *)target, HEAP, -1, MAP_ANON | MAP_PRIVATE);
	});
}

T_DECL(range_mach_vm_map_with_bad_hint,
    "ensure mach_vm_map fails when hint is above range")
{
	do_test(^{
		struct mach_vm_range range = get_range(HEAP);
		mach_vm_address_t addr = range.max_address + 0x100000000;

		set_allocation_size(PAGE_SIZE);

		/*
		 * unlike mmap & vm_allocate, mach_vm_map should fail when given a hint
		 * out with the target range.
		 */
		int ret = mach_vm_map(mach_task_self(), &addr, _allocation_size,
		(mach_vm_offset_t)0, VM_FLAGS_ANYWHERE, MACH_PORT_NULL,
		(memory_object_offset_t)0, FALSE, VM_PROT_DEFAULT, VM_PROT_ALL,
		VM_INHERIT_DEFAULT);
		T_QUIET; T_EXPECT_EQ(ret, KERN_NO_SPACE, "expected KERN_NO_SPACE");
	});
}

T_DECL(range_mach_vm_remap_default,
    "ensure mach_vm_remap is successful in default range")
{
	do_test(^{
		vm_prot_t curprot;
		vm_prot_t maxprot;

		set_allocation_size(PAGE_SIZE);

		mach_vm_address_t addr = assert_allocate_in_range(DEFAULT, 0, RANGE_DEFAULT_FLAGS);
		mach_vm_address_t target = addr + _allocation_size;

		int ret = mach_vm_remap(mach_task_self(), &target, _allocation_size,
		(mach_vm_offset_t)0, VM_FLAGS_ANYWHERE, mach_task_self(),
		addr, FALSE, &curprot, &maxprot, VM_INHERIT_NONE);
		T_QUIET; T_EXPECT_EQ(ret, KERN_SUCCESS, "expected KERN_SUCCESS");
	});
}

T_DECL(range_mach_vm_remap_heap_with_hint,
    "ensure mach_vm_remap is successful in heap range")
{
	do_test(^{
		vm_prot_t curprot;
		vm_prot_t maxprot;

		set_allocation_size(PAGE_SIZE);

		mach_vm_address_t addr = assert_allocate_in_range(HEAP, 0, RANGE_HEAP_FLAGS);
		mach_vm_address_t target = addr + _allocation_size;

		int ret = mach_vm_remap(mach_task_self(), &target, _allocation_size,
		(mach_vm_offset_t)0, VM_FLAGS_ANYWHERE, mach_task_self(),
		addr, FALSE, &curprot, &maxprot, VM_INHERIT_NONE);
		T_QUIET; T_EXPECT_EQ(ret, KERN_SUCCESS, "expected KERN_SUCCESS");
		assert_in_heap_range(target);
	});
}

T_DECL(range_mach_vm_remap_heap,
    "ensure mach_vm_remap remains in same range")
{
	do_test(^{
		vm_prot_t curprot;
		vm_prot_t maxprot;

		set_allocation_size(PAGE_SIZE);

		mach_vm_address_t addr = assert_allocate_in_range(HEAP, 0, RANGE_HEAP_FLAGS);
		mach_vm_address_t target = 0;

		int ret = mach_vm_remap(mach_task_self(), &target, _allocation_size,
		(mach_vm_offset_t)0, VM_FLAGS_ANYWHERE, mach_task_self(),
		addr, FALSE, &curprot, &maxprot, VM_INHERIT_NONE);
		T_EXPECT_EQ(ret, KERN_SUCCESS, "expected KERN_SUCCESS");
		assert_in_heap_range(target);
	});
}

static void
ensure_range()
{
	struct mach_vm_range def = get_range(DEFAULT);
	struct mach_vm_range heap = get_range(HEAP);

	T_EXPECT_GT(heap.min_address, def.max_address,
	    "ranges should not overlap");
	T_EXPECT_LE(heap.max_address, MAX_VM_ADDRESS,
	    "expected max <= %llx", MAX_VM_ADDRESS);
	T_EXPECT_EQ(heap.min_address,
	    heap.min_address & (unsigned long)~0x1FFFFF,
	    "expected alignment on 2MB TT boundary");
}

static void
ensure_child_range()
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

T_DECL(range_ensure_bounds, "ensure ranges respect map bounds")
{
	do_test(^{
		parent_default = get_range(DEFAULT);
		parent_heap = get_range(HEAP);

		ensure_range();

		for (uint32_t i = 0; i < CHILD_PROCESS_COUNT; i++) {
		        fork_child_test(ensure_child_range);
		}
	});
}
