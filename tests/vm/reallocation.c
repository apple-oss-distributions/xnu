#include <darwintest.h>

#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

#define CONCAT_(a, b) a ## b
#define CONCAT(a, b) CONCAT_(a, b)
#define UNIQUE(name) CONCAT(__ ## name, __LINE__)

/*
 * Very simple signal handler for arbitrary signal to jump to wherever
 * JB_RECOVERY was set.
 */
static jmp_buf jb_recovery;
static void
handler(int sig, siginfo_t *info, void *context)
{
	(void) sig;
	(void) info;
	(void) context;
	longjmp(jb_recovery, 0);
}
static struct sigaction new_action, old_action;

/*
 * An easy way to declare some code might get signalled (e.g., segfault), and
 * how we want to recover.
 *
 *  Example:
 *
 *      MAYBE_SIG__START(SIGSEGV);
 *      char x = *((char *) 0);
 *      MAYBE_SIG__OCCURED(SIGSEGV);
 *      printf("segfault occured\n");
 *      MAYBE_SIG__END(SIGSEGV);
 *
 *  Don't nest these statements.
 *
 *  If you're doing something local to the MAYBE_SIG__START scope that may be
 *  optimized away by the compiler (e.g., dereferencing something and throwing
 *  away the value to trigger a segfault), ensure that the "volatile" keyword
 *  is used to prevent this optimization.
 */
#define MAYBE_SIG__START(sig)                                                  \
    volatile bool UNIQUE(signalled) = false;                                   \
    new_action.sa_sigaction = handler;                                         \
    new_action.sa_flags = SA_SIGINFO;                                          \
    (void) sigaction(sig, &new_action, &old_action);                           \
    (void) setjmp(jb_recovery);                                                \
    if (!UNIQUE(signalled)) {                                                  \
	UNIQUE(signalled) = true;
#define MAYBE_SIG__OCCURED(sig)                                                \
    } else {
#define MAYBE_SIG__END(sig)                                                    \
    }                                                                          \
    sigaction(sig, &old_action, NULL);

#define OBSTACLE_SIZE (1 << 16)

/**
 * Define some wrappers around the non-mach versions of vm_allocate,
 * vm_deallocate, and vm_reallocate so that we can call them with mach_vm_*
 * parameters on systems where the types may be different sizes.
 *
 * This way, we can easily test both variants of vm_reallocate.
 */

typedef typeof(mach_vm_allocate) allocate_func_t;
typedef typeof(mach_vm_deallocate) deallocate_func_t;
typedef typeof(mach_vm_reallocate) reallocate_func_t;

kern_return_t
vm_allocate_wrap(
	vm_map_t            map,
	mach_vm_address_t  *mach_addr_inout,
	mach_vm_size_t      mach_size,
	int                 flags)
{
	kern_return_t   kr;
	vm_address_t    addr_inout = (vm_address_t)(*mach_addr_inout);
	vm_size_t       size       = (vm_size_t)mach_size;

	T_QUIET; T_ASSERT_EQ((mach_vm_address_t) addr_inout, *mach_addr_inout, "non-mach addr is not truncated");
	T_QUIET; T_ASSERT_EQ((mach_vm_size_t) size, mach_size, "non-mach size is not truncated");

	kr = vm_allocate(map, &addr_inout, (vm_size_t) size, flags);
	*mach_addr_inout = addr_inout;
	return kr;
}

kern_return_t
vm_deallocate_wrap(
	vm_map_t            map,
	mach_vm_address_t   mach_addr,
	mach_vm_size_t      mach_size)
{
	vm_address_t    addr = (vm_address_t) mach_addr;
	vm_size_t       size = (vm_size_t) mach_size;

	T_QUIET; T_ASSERT_EQ((mach_vm_address_t) addr, mach_addr, "non-mach addr is not truncated");
	T_QUIET; T_ASSERT_EQ((mach_vm_size_t) size, mach_size, "non-mach size is not truncated");

	return vm_deallocate(map, addr, size);
}

kern_return_t
vm_reallocate_wrap(
	vm_map_t            map,
	mach_vm_address_t   mach_src,
	mach_vm_size_t      mach_src_size,
	mach_vm_address_t  *mach_dst_inout,
	mach_vm_size_t      mach_dst_size,
	mach_vm_offset_t    mach_align_mask,
	int                 options,
	int                 flags)
{
	kern_return_t   kr;
	vm_offset_t     align_mask = (vm_offset_t)mach_align_mask;
	vm_address_t    src        = (vm_address_t)mach_src;
	vm_address_t    dst_inout  = (vm_address_t)(*mach_dst_inout);
	vm_size_t       src_size   = (vm_size_t)mach_src_size;
	vm_size_t       dst_size   = (vm_size_t)mach_dst_size;

	T_QUIET; T_ASSERT_EQ((mach_vm_address_t) src, mach_src, "non-mach src is not truncated");
	T_QUIET; T_ASSERT_EQ((mach_vm_size_t) src_size, mach_src_size, "non-mach src size is not truncated");
	T_QUIET; T_ASSERT_EQ((mach_vm_address_t) dst_inout, *mach_dst_inout, "non-mach dst is not truncated");
	T_QUIET; T_ASSERT_EQ((mach_vm_size_t) dst_size, mach_dst_size, "non-mach dst size is not truncated");
	T_QUIET; T_ASSERT_EQ((mach_vm_offset_t) align_mask, mach_align_mask, "non-mach align mask is not truncated");

	kr = vm_reallocate(map, src, src_size, &dst_inout, dst_size, align_mask, options, flags);
	*mach_dst_inout = dst_inout;
	return kr;
}

/*
 * De-duplicate and simplify allocation code, since we always create something
 * to reallocate, and sometimes add an obstacle directly after it.
 *
 * Produces the following layout:
 *
 *  ┌─────────────────┐◄─── allocation
 *  │                 │
 *  │     SOURCE      │
 *  │                 │
 *  ├────┬────────────┤◄─── allocation + src_size    ┐C O  ┐E
 *  │    │ FREE PAGE  │                              │R B  │L
 *  │    │(NOT MAPPED)│                              │E S  │S
 *  │    ├────────────┤◄─── obstacle = allocation    │A T  │E
 *  │    │            │              + src_size      │T A  │
 *  │    │  OBSTACLE  │              + PAGE_SIZE     │E C  │I
 *  │    │            │                              │  L  │N
 *  │    ├────────────┤◄─── obstacle + OBSTACLE_SIZE │  E  │
 *  │    │ FREE PAGE  │                              │     │P
 *  │    │(NOT MAPPED)│                              │     │L
 *  │    └────────────┤◄─── obstacle + OBSTACLE_SIZE ┘     │A
 *  │                 │              + PAGE_SIZE           │C
 *  │ GUARANTEED HOLE │                                    │E
 *  │   (NOT MAPPED)  │                                    │
 *  │                 │                                    │
 *  └─────────────────┘◄─── allocation + dst_size          ┘
 */
static void
allocate_source_obstacle(
	allocate_func_t         alloc_func,
	deallocate_func_t       dealloc_func,
	mach_vm_address_t      *allocation,
	mach_vm_size_t          src_size,
	mach_vm_size_t          dst_size,
	mach_vm_address_t      *obstacle,
	bool                    create_obstacle)
{
	kern_return_t   kr;
	mach_vm_size_t  alloc_size;
	mach_vm_size_t  dealloc_size;

	/*
	 * For in-place mode, ensure we have enough space to grow in-place by
	 * allocating the destination size, and then deallocating everything
	 * except for the source size.
	 *
	 * For out-of-place mode, ensure we can't grow in-place by allocating
	 * enough space for both the source and obstacle and then manually
	 * deallocate the space between the source and obstacle. This ensures the
	 * obstacle is just off the end of the source.
	 */
	if (create_obstacle) {
		alloc_size = src_size + PAGE_SIZE + OBSTACLE_SIZE + PAGE_SIZE;
		dealloc_size = PAGE_SIZE;
	} else {
		alloc_size = dst_size;
		dealloc_size = dst_size - src_size;
	}

	*allocation = (mach_vm_address_t)NULL;
	kr = alloc_func(mach_task_self(), allocation, alloc_size, VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocate source+");

	kr = dealloc_func(mach_task_self(), *allocation + src_size, dealloc_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate region between source and obstacle");

	if (create_obstacle) {
		*obstacle = *allocation + src_size + PAGE_SIZE;
		kr = dealloc_func(mach_task_self(), *obstacle + OBSTACLE_SIZE, PAGE_SIZE);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate free page after obstacle");
	}
}

/*
 * Beware, annoyingly the T_ASSERT_MACH_SUCCESS will consume any T_QUIET you've
 * applied to a test if the test macro calls get_user_tag inline.
 */
static vm_region_extended_info_data_t
get_region_info(vm_address_t address)
{
	kern_return_t                   kr;
	vm_size_t                       region_size;
	vm_address_t                    region_addr       = address;
	mach_msg_type_number_t          region_info_count = VM_REGION_EXTENDED_INFO_COUNT;
	vm_region_extended_info_data_t  region_info;

	kr = mach_vm_region(mach_task_self(),
	    (mach_vm_address_t *)&region_addr,
	    (mach_vm_size_t *)&region_size,
	    VM_REGION_EXTENDED_INFO,
	    (vm_region_info_t)&region_info,
	    &region_info_count,
	    &(mach_port_t){0});
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_region");

	return region_info;
}

/*
 * Wrapper to call mach_vm_region to get the user tag associated with an address.
 */
static unsigned int
get_user_tag(vm_address_t address)
{
	return get_region_info(address).user_tag;
}

/*
 * Wrapper to call mach_vm_region to query whether address has an external pager.
 */
static unsigned int
addr_has_external_pager(vm_address_t address)
{
	return get_region_info(address).external_pager;
}

/*
 * Size and layout configurations to run for each test.
 */
static struct reallocation_spec {
	mach_vm_size_t      src_size;       /* Initial allocation size. */
	mach_vm_size_t      dst_size;       /* Reallocated size. */
	mach_vm_offset_t    align_mask;     /* Arg. */
	int                 options;        /* Arg. */
	int                 flags;          /* Arg. */
	char                user_tag;       /* Arg. */
	mach_vm_offset_t    dst_offset;     /* When vm_reallocate is called, dst=src+dst_offset. */
	bool                out_of_place;   /* Create an obstacle to force out-of-place. */
} specs[] = {
	{.src_size = 64 * 1024, .dst_size = 192 * 1024, .out_of_place = false, .align_mask = 0, .options = VM_REALLOCATE_DEALLOCATE_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 0, .dst_offset = 0},                   /* Small in-place. */
	{.src_size = 64 * 1024, .dst_size = 192 * 1024, .out_of_place = true, .align_mask = 0, .options = VM_REALLOCATE_DEALLOCATE_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 10, .dst_offset = 0},                   /* Small out-of-place. */
	{.src_size = 2 * 1024 * 1024, .dst_size = 4 * 1024 * 1024, .out_of_place = false, .align_mask = 0, .options = VM_REALLOCATE_DEALLOCATE_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 20, .dst_offset = 0},       /* Most common libmalloc in-place case. */
	{.src_size = 2 * 1024 * 1024, .dst_size = 4 * 1024 * 1024, .out_of_place = true, .align_mask = 0, .options = VM_REALLOCATE_DEALLOCATE_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 30, .dst_offset = 0},        /* Most common libmalloc out-of-place case. */
	{.src_size = 64 * 1024 * 1024, .dst_size = 192 * 1024 * 1024, .out_of_place = false, .align_mask = 0, .options = VM_REALLOCATE_DEALLOCATE_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 40, .dst_offset = 0},    /* Large case spanning >1 vm entry in-place. */
	{.src_size = 64 * 1024 * 1024, .dst_size = 192 * 1024 * 1024, .out_of_place = true, .align_mask = 0, .options = VM_REALLOCATE_DEALLOCATE_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 50, .dst_offset = 0},     /* Large case spanning >1 vm entry out-of-place. */

	{.src_size = 64 * 1024, .dst_size = 192 * 1024, .out_of_place = false, .align_mask = 0, .options = VM_REALLOCATE_ZERO_FILL_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 0, .dst_offset = 0},                  /* (zero-fill) Small in-place. */
	{.src_size = 64 * 1024, .dst_size = 192 * 1024, .out_of_place = true, .align_mask = 0, .options = VM_REALLOCATE_ZERO_FILL_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 10, .dst_offset = 0},                  /* (zero-fill) Small out-of-place. */
	{.src_size = 2 * 1024 * 1024, .dst_size = 4 * 1024 * 1024, .out_of_place = false, .align_mask = 0, .options = VM_REALLOCATE_ZERO_FILL_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 20, .dst_offset = 0},      /* (zero-fill) Most common libmalloc in-place case. */
	{.src_size = 2 * 1024 * 1024, .dst_size = 4 * 1024 * 1024, .out_of_place = true, .align_mask = 0, .options = VM_REALLOCATE_ZERO_FILL_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 30, .dst_offset = 0},       /* (zero-fill) Most common libmalloc out-of-place case. */
	{.src_size = 64 * 1024 * 1024, .dst_size = 192 * 1024 * 1024, .out_of_place = false, .align_mask = 0, .options = VM_REALLOCATE_ZERO_FILL_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 40, .dst_offset = 0},  /* (zero-fill) Large case spanning >1 vm entry in-place. */
	{.src_size = 64 * 1024 * 1024, .dst_size = 192 * 1024 * 1024, .out_of_place = true, .align_mask = 0, .options = VM_REALLOCATE_ZERO_FILL_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 50, .dst_offset = 0},   /* (zero-fill) Large case spanning >1 vm entry out-of-place. */

	{.src_size = 2 * 1024 * 1024, .dst_size = 4 * 1024 * 1024, .out_of_place = true, .align_mask = (1 << 16) - 1, .options = VM_REALLOCATE_DEALLOCATE_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 60, .dst_offset = 0},   /* 64 KB alignment. */
	{.src_size = 2 * 1024 * 1024, .dst_size = 4 * 1024 * 1024, .out_of_place = true, .align_mask = (1 << 20) - 1, .options = VM_REALLOCATE_DEALLOCATE_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 70, .dst_offset = 0},   /* 1 MB alignment. */
	{.src_size = 2 * 1024 * 1024, .dst_size = 4 * 1024 * 1024, .out_of_place = true, .align_mask = (1 << 10) - 1, .options = VM_REALLOCATE_DEALLOCATE_SOURCE, .flags = VM_FLAGS_ANYWHERE, .user_tag = 80, .dst_offset = 0},   /* sub-page alignment (should round to page-aligned). */

	{.src_size = 64 * 1024, .dst_size = 192 * 1024, .out_of_place = true, .align_mask = 0, .options = VM_REALLOCATE_DEALLOCATE_SOURCE, .flags = VM_FLAGS_FIXED, .user_tag = 10, .dst_offset = 0},                 /* Small out-of-place (fixed addr). */
	{.src_size = 2 * 1024 * 1024, .dst_size = 4 * 1024 * 1024, .out_of_place = true, .align_mask = 0, .options = VM_REALLOCATE_DEALLOCATE_SOURCE, .flags = VM_FLAGS_FIXED, .user_tag = 30, .dst_offset = 0},      /* Most common libmalloc out-of-place case (fixed addr). */
	{.src_size = 64 * 1024 * 1024, .dst_size = 192 * 1024 * 1024, .out_of_place = true, .align_mask = 0, .options = VM_REALLOCATE_DEALLOCATE_SOURCE, .flags = VM_FLAGS_FIXED, .user_tag = 50, .dst_offset = 0},   /* Large case spanning >1 vm entry out-of-place (fixed addr). */

	{.src_size = 16 * 1024, .dst_size = 32 * 1024, .out_of_place = true, .align_mask = 0, .options = VM_REALLOCATE_DEALLOCATE_SOURCE, .flags = VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, .user_tag = 42, .dst_offset = 0},     /* Overwrite part of the obstacle. */
};

/*
 * Tests the following things:
 *  - vm_reallocate calls succeeds
 *  - resulting destination has the correct data
 *  - source is unmapped if out-of-place (& not zero-fill) reallocation occurred
 *  - user tag is set correctly
 *  - alignment is set correctly
 */
void
do_spec_tests(
	allocate_func_t     alloc_func,
	deallocate_func_t   dealloc_func,
	reallocate_func_t   realloc_func)
{
	kern_return_t               kr;
	mach_vm_address_t           src      = (vm_address_t)NULL;
	mach_vm_address_t           dst      = (vm_address_t)NULL;
	mach_vm_address_t           dst_orig = dst;
	mach_vm_address_t           obstacle = (vm_address_t)NULL;
	struct reallocation_spec   *spec;
	unsigned long               n_specs;
	unsigned int                user_tag;
	volatile bool               segfault;

	n_specs = sizeof(specs) / sizeof(struct reallocation_spec);
	T_LOG("testing %lu vm_reallocate specs", n_specs);
	for (unsigned long spec_id = 0; spec_id < n_specs; spec_id++) {
		spec = &specs[spec_id];
		T_LOG("spec: src_size=%llu, dst_size=%llu, out_of_place=%d, align_mask=0x%llx, user_tag=%u, behavior=%d, flags=0x%x, dst_offset=0x%llx",
		    spec->src_size,
		    spec->dst_size,
		    spec->out_of_place,
		    spec->align_mask,
		    spec->user_tag,
		    spec->options,
		    spec->flags,
		    spec->dst_offset);
		T_SETUPBEGIN;
		src = (mach_vm_address_t) NULL;       /* don't use the last test's address as a hint. */
		allocate_source_obstacle(
			alloc_func,
			dealloc_func,
			&src,
			spec->src_size,
			spec->dst_size,
			&obstacle,
			spec->out_of_place);
		for (vm_size_t i = 0; i < spec->src_size; i++) {
			((char *)src)[i] = (char)i;
		}
		T_SETUPEND;

		if (spec->flags & VM_FLAGS_OVERWRITE) {
			/*
			 * Overwrite the obstacle.
			 */
			dst = obstacle;
		} else if (!(spec->flags & VM_FLAGS_ANYWHERE)) {
			/*
			 * Find a suitable location to reallocate into.
			 */
			kr = alloc_func(mach_task_self(), &dst, spec->dst_size, VM_FLAGS_ANYWHERE);
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocate fixed target");
			kr = dealloc_func(mach_task_self(), dst, spec->dst_size);
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate fixed target");
		} else {
			dst = src + spec->dst_offset;
		}
		dst_orig = dst;
		kr = realloc_func(mach_task_self(),
		    src,
		    spec->src_size,
		    &dst,
		    spec->dst_size,
		    spec->align_mask,
		    spec->options,
		    spec->flags | VM_MAKE_TAG(spec->user_tag));
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "reallocate source");
		T_QUIET; T_ASSERT_NOTNULL((void *)dst, "destination not null");
		if (spec->dst_size > spec->src_size) {
			if (!(spec->flags & VM_FLAGS_ANYWHERE)) { /* VM_FLAGS_FIXED. */
				T_QUIET; T_ASSERT_EQ(dst, dst_orig, "dst (out = 0x%llx) must not change (in = 0x%llx) if VM_FLAGS_FIXED set", dst, dst_orig);
			} else { /* VM_FLAGS_ANYWHERE. */
				T_QUIET; T_ASSERT_EQ(dst != src, spec->out_of_place, "out of place reallocation (dst=0x%llx, src=0x%llx)", dst, src);
				T_QUIET; T_ASSERT_GE(dst, src + spec->dst_offset, "dst (0x%llx) must be >= than hint (0x%llx)", dst, src + spec->dst_offset);
			}
		}

		/*
		 * The destination should be properly aligned if it was relocated.
		 */
		if (spec->out_of_place && spec->dst_size > spec->src_size) {
			T_QUIET; T_EXPECT_EQ(dst & spec->align_mask, 0ull, "destination aligned to mask");
		}

		/*
		 * The destination should have uniform permissions.
		 */
		mach_vm_address_t addr       = dst;
		mach_vm_address_t end_of_dst = dst + spec->dst_size;
		while (addr < end_of_dst) {
			vm_region_submap_info_data_64_t info  = {};
			mach_msg_type_number_t          count = VM_REGION_SUBMAP_INFO_COUNT_64;
			mach_vm_size_t                  size  = 0;
			natural_t                       depth = 99;
			kr = mach_vm_region_recurse(
				mach_task_self(),
				&addr,
				&size,
				&depth,
				(vm_region_recurse_info_t)&info,
				&count);
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "get region info");
			T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ | VM_PROT_WRITE, "current protections");
			T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE, "max protections");

			addr += size;
		}

		/*
		 * The entire destination should be mapped with the correct data.
		 */
		segfault = false;
		MAYBE_SIG__START(SIGSEGV);
		for (vm_size_t i = 0; i < spec->src_size; i++) {
			volatile char x = ((char *)dst)[i];
			if (x != (char)i) {
				T_EXPECTFAIL;
				T_EXPECT_EQ(x, (char)i, "integrity failed: byte at offset %lu was 0x%x, expected 0x%x", (unsigned long) i, x, (char)i);
				break;
			}
		}
		MAYBE_SIG__OCCURED(SIGSEGV);
		segfault = true;
		MAYBE_SIG__END(SIGSEGV);
		T_QUIET; T_EXPECT_FALSE(segfault, "destination segfault (beginning)");

		/*
		 * The end of the destination should contain zeroes.
		 */
		segfault = false;
		MAYBE_SIG__START(SIGSEGV);
		for (vm_size_t i = spec->src_size; i < spec->dst_size; i++) {
			volatile char x = ((char *)dst)[i];
			if (x != 0) {
				T_EXPECTFAIL;
				T_EXPECT_EQ(x, 0, "new memory is not zeroed: byte at offset %lu was 0x%x", (unsigned long) i, x);
				break;
			}
		}
		MAYBE_SIG__OCCURED(SIGSEGV);
		segfault = true;
		MAYBE_SIG__END(SIGSEGV);
		T_QUIET; T_EXPECT_FALSE(segfault, "destination segfault (end)");

		/*
		 * Ensure the user tag is set for the relocated region.
		 */
		if (spec->out_of_place) {
			user_tag = get_user_tag(dst);
			T_QUIET; T_EXPECT_EQ(user_tag, (unsigned int) spec->user_tag, "relocated region correct tag");
		}

		/*
		 * Ensure the expanded region's tag is set, or is using the source tag
		 * if there was no new tag specified.
		 */
		if (spec->dst_size > spec->src_size) {
			user_tag = get_user_tag(dst + spec->src_size);
			T_QUIET; T_EXPECT_EQ(user_tag, (unsigned int) spec->user_tag, "expanded region correct tag");
		}

		/*
		 * If out-of-place and not zero-filled then source should be unmapped.
		 */
		if (spec->out_of_place && spec->dst_size > spec->src_size && spec->options != VM_REALLOCATE_ZERO_FILL_SOURCE) {
			/*
			 * Dereference the first address.
			 */
			segfault = false;
			MAYBE_SIG__START(SIGSEGV);
			volatile char x = ((char *)src)[0];
			(void) x;
			MAYBE_SIG__OCCURED(SIGSEGV);
			segfault = true;
			MAYBE_SIG__END(SIGSEGV);
			T_QUIET; T_ASSERT_TRUE(segfault, "first address of source unmapped");

			/*
			 * Dereference the last address.
			 */
			segfault = false;
			MAYBE_SIG__START(SIGSEGV);
			volatile char x = ((char *)src)[spec->src_size - 1];
			(void) x;
			MAYBE_SIG__OCCURED(SIGSEGV);
			segfault = true;
			MAYBE_SIG__END(SIGSEGV);
			T_QUIET; T_ASSERT_TRUE(segfault, "last address of source unmapped");
		}

		/*
		 * If out-of-place and zero-filled then source should be all zeros.
		 */
		if (spec->out_of_place && spec->options == VM_REALLOCATE_ZERO_FILL_SOURCE) {
			segfault = false;
			MAYBE_SIG__START(SIGSEGV);
			for (vm_size_t i = 0; i < spec->src_size; i++) {
				if (((char *)src)[i]) {
					T_EXPECT_FALSE(true, "zero-filled source was non-zero");
					break;
				}
			}
			MAYBE_SIG__OCCURED(SIGSEGV);
			segfault = true;
			MAYBE_SIG__END(SIGSEGV);
			T_QUIET; T_ASSERT_FALSE(segfault, "zero-filled but source unmapped");
		}


		/*
		 * Clean up everything we've allocated and reallocated. We overwrite the
		 * obstacle when VM_FLAGS_OVERWRITE are set, so don't double-free it.
		 */
		if (spec->out_of_place) {
			T_QUIET; T_EXPECT_MACH_SUCCESS(dealloc_func(mach_task_self(), obstacle, OBSTACLE_SIZE), "deallocate obstacle");
		}
		if (!(spec->flags & VM_FLAGS_OVERWRITE)) {
			T_QUIET; T_EXPECT_MACH_SUCCESS(dealloc_func(mach_task_self(), dst, spec->dst_size), "deallocate destination");
		}
	}
	T_LOG("all vm_reallocate specs done");
}

/**
 * Test both mach and non-mach variants of vm_reallocate with valid arguments.
 */
T_DECL(reallocation_valid_arguments,
    "basic testing of observable vm_reallocate behavior with reasonable arguments")
{
	T_LOG("Testing mach_vm_reallocate");
	do_spec_tests(mach_vm_allocate, mach_vm_deallocate, mach_vm_reallocate);
	T_LOG("Testing vm_reallocate");
	do_spec_tests(vm_allocate_wrap, vm_deallocate_wrap, vm_reallocate_wrap);
}


void
do_invalid_tests(
	allocate_func_t     alloc_func,
	deallocate_func_t   dealloc_func,
	reallocate_func_t   realloc_func)
{
	kern_return_t       kr;
	mach_vm_size_t      src_size = 2 * 1024 * 1024;
	mach_vm_size_t      dst_size = 4 * 1024 * 1024;
	mach_vm_address_t   src      = (vm_address_t)NULL;
	mach_vm_address_t   dst      = (vm_address_t)NULL;
	mach_vm_address_t   obstacle = (vm_address_t)NULL;

	/*
	 * Allocate a valid source and obstacle.
	 */
	T_SETUPBEGIN;
	allocate_source_obstacle(alloc_func, dealloc_func, &src, src_size, dst_size, &obstacle, true);
	for (vm_size_t i = 0; i < src_size; i++) {
		((char *)src)[i] = (char)i; /* We'll check integrity later. */
	}
	T_SETUPEND;

	/*
	 * Invalid argument: NULL source.
	 */
	dst = (vm_address_t)NULL;
	kr = realloc_func(mach_task_self(),
	    (vm_address_t) NULL,
	    src_size,
	    &dst,
	    dst_size,
	    0,
	    VM_REALLOCATE_DEALLOCATE_SOURCE,
	    VM_FLAGS_ANYWHERE);
	T_ASSERT_NE(kr, KERN_SUCCESS, "bad argument: NULL source");

	/*
	 * Invalid argument: Unmapped source.
	 */
	dst = (vm_address_t)NULL;
	kr = realloc_func(mach_task_self(),
	    obstacle + OBSTACLE_SIZE, /* This page is guaranteed to be unmapped. */
	    PAGE_SIZE,
	    &dst,
	    dst_size,
	    0,
	    VM_REALLOCATE_DEALLOCATE_SOURCE,
	    VM_FLAGS_ANYWHERE);
	T_ASSERT_NE(kr, KERN_SUCCESS, "bad argument: unmapped source");

	/*
	 * Invalid argument: Unaligned source.
	 */
	dst = (vm_address_t)NULL;
	kr = realloc_func(mach_task_self(),
	    src + (PAGE_SIZE / 2), /* Not page aligned. */
	    src_size,
	    &dst,
	    dst_size,
	    0,
	    VM_REALLOCATE_DEALLOCATE_SOURCE,
	    VM_FLAGS_ANYWHERE);
	T_ASSERT_NE(kr, KERN_SUCCESS, "bad argument: source not page-aligned");

	/*
	 * Invalid argument: Source size is zero.
	 */
	dst = (vm_address_t)NULL;
	kr = realloc_func(mach_task_self(),
	    src,
	    0,
	    &dst,
	    dst_size,
	    0,
	    VM_REALLOCATE_DEALLOCATE_SOURCE,
	    VM_FLAGS_ANYWHERE);
	T_ASSERT_NE(kr, KERN_SUCCESS, "bad argument: source size is zero");

	/*
	 * Invalid argument: Destination is unaligned (VM_FLAGS_FIXED).
	 */
	dst = src + src_size + (PAGE_SIZE / 2);
	kr = realloc_func(mach_task_self(),
	    src,
	    src_size,
	    &dst,
	    dst_size,
	    0,
	    VM_REALLOCATE_DEALLOCATE_SOURCE,
	    VM_FLAGS_FIXED);
	T_ASSERT_NE(kr, KERN_SUCCESS, "bad argument: destination not page-aligned");

	/*
	 * Invalid argument: VM_FLAGS_FIXED impossible, no overwrite.
	 */
	dst = obstacle;
	kr = realloc_func(mach_task_self(),
	    src,
	    src_size,
	    &dst,
	    dst_size,
	    0,
	    VM_REALLOCATE_DEALLOCATE_SOURCE,
	    VM_FLAGS_FIXED);
	T_ASSERT_NE(kr, KERN_SUCCESS, "bad argument: VM_FLAGS_FIXED (no overwrite) on top of obstacle");

	/*
	 * Invalid argument: Destination size is not page aligned.
	 */
	dst = (vm_address_t)NULL;
	kr = realloc_func(mach_task_self(),
	    src,
	    src_size,
	    &dst,
	    dst_size + (PAGE_SIZE / 2),
	    0,
	    VM_REALLOCATE_DEALLOCATE_SOURCE,
	    VM_FLAGS_ANYWHERE);
	T_ASSERT_NE(kr, KERN_SUCCESS, "bad argument: destination size not page-aligned");

	/*
	 * Invalid layout: Source size too large.
	 */
	kr = realloc_func(mach_task_self(),
	    src,
	    src_size + PAGE_SIZE,
	    &dst, dst_size,
	    0,
	    VM_REALLOCATE_DEALLOCATE_SOURCE,
	    VM_FLAGS_ANYWHERE);
	T_EXPECT_NE(kr, KERN_SUCCESS, "bad argument: smaller source than described");

	/*
	 * As a final check, the source should still be valid after all of these
	 * aborted calls. Try writing to the whole thing, reallocating it, and
	 * checking the data integrity at the destination.
	 */

	/*
	 * Integrity OK before reallocation.
	 */
	for (vm_size_t i = 0; i < src_size; i++) {
		char x = ((char *)src)[i];
		if (x != (char)i) {
			T_EXPECTFAIL;
			T_EXPECT_EQ(x, (char)i, "source integrity failed: byte at offset %lu was 0x%x, expected 0x%x", (unsigned long) i, x, (char)i);
			break;
		}
	}

	/*
	 * Reallocate with valid arguments.
	 */
	kr = realloc_func(mach_task_self(),
	    src,
	    src_size,
	    &dst,
	    dst_size,
	    0,
	    VM_REALLOCATE_DEALLOCATE_SOURCE,
	    VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "reallocation sanity-check");
	T_QUIET; T_ASSERT_NOTNULL((void *)dst, "reallocation not NULL");

	/*
	 * Integrity OK after reallocation.
	 */
	for (vm_size_t i = 0; i < src_size; i++) {
		char x = ((char *)dst)[i];
		if (x != (char)i) {
			T_EXPECTFAIL;
			T_EXPECT_EQ(x, (char)i, "destination integrity failed: byte at offset %lu was 0x%x, expected 0x%x", (unsigned long) i, x, (char)i);
			break;
		}
	}

	/*
	 * Deallocation OK.
	 */
	T_QUIET; T_EXPECT_MACH_SUCCESS(dealloc_func(mach_task_self(), dst, dst_size), "deallocate destination");

	/*
	 * Cleanup.
	 */
	T_QUIET; T_EXPECT_MACH_SUCCESS(dealloc_func(mach_task_self(), obstacle, OBSTACLE_SIZE), "deallocate obstacle");
}


T_DECL(reallocation_invalid_arguments,
    "ensure that sanitization properly catches bad inputs")
{
	T_LOG("Testing mach_vm_reallocate");
	do_invalid_tests(mach_vm_allocate, mach_vm_deallocate, mach_vm_reallocate);
	T_LOG("Testing vm_reallocate");
	do_invalid_tests(vm_allocate_wrap, vm_deallocate_wrap, vm_reallocate_wrap);
}

void
do_holes_test(
	allocate_func_t     alloc_func,
	deallocate_func_t   dealloc_func,
	reallocate_func_t   realloc_func)
{
	kern_return_t       kr;
	mach_vm_size_t      src_size = 2 * 1024 * 1024;
	mach_vm_size_t      dst_size = 4 * 1024 * 1024;
	mach_vm_address_t   src      = (vm_address_t)NULL;
	mach_vm_address_t   dst      = (vm_address_t)NULL;

	T_SETUPBEGIN;
	kr = alloc_func(mach_task_self(), (mach_vm_address_t *)&src, src_size, VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "create source");
	kr = dealloc_func(mach_task_self(), src + src_size / 2, PAGE_SIZE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "put hole in source");
	T_SETUPEND;

	kr = realloc_func(mach_task_self(), src, src_size, &dst, dst_size, 0, VM_REALLOCATE_DEALLOCATE_SOURCE, VM_FLAGS_ANYWHERE);
	T_EXPECT_NE(kr, KERN_SUCCESS, "Holes in source should fail");

	kr = dealloc_func(mach_task_self(), src, src_size / 2);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate source before hole");
	kr = dealloc_func(mach_task_self(), src + src_size / 2 + PAGE_SIZE, src_size / 2 - PAGE_SIZE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate source after hole");
}

T_DECL(reallocation_holes,
    "ensure that improperly described source layouts generate EXC_GUARD")
{
	T_LOG("Testing mach_vm_reallocate");
	do_holes_test(mach_vm_allocate, mach_vm_deallocate, mach_vm_reallocate);
	T_LOG("Testing vm_reallocate");
	do_holes_test(vm_allocate_wrap, vm_deallocate_wrap, vm_reallocate_wrap);
}

T_DECL(realloction_file,
    "ensure that reallocating part of an mmapped file works as expected")
{
	mach_vm_size_t whole_src_size = 3 * PAGE_SIZE;
	mach_vm_size_t reallocate_src_size = PAGE_SIZE;
	mach_vm_size_t reallocate_dst_size = 2 * PAGE_SIZE;
	/*
	 * Memory layout:
	 *   Before: [... [FILE PAGE 0][FILE PAGE 1][FILE PAGE 2] ...]
	 *   After:  [... [FILE PAGE 0][   HOLE    ][FILE PAGE 2] ... [FILE PAGE 1][ANON PAGE] ...]
	 */


	/*
	 * Create some data that we'll use to check the integrity of the file.
	 */
	mach_vm_address_t truth_buf_addr = 0;
	T_QUIET; T_ASSERT_MACH_SUCCESS(
		mach_vm_allocate(mach_task_self(), &truth_buf_addr, whole_src_size, VM_FLAGS_ANYWHERE),
		"allocate ground truth buffer");
	int *truth_buf = (int *)truth_buf_addr;
	for (int i = 0; i < (whole_src_size / sizeof(int)); i++) {
		truth_buf[i] = i;
	}

	/*
	 * Create a file in /tmp/ and fill it with our contents.
	 */
	const char *filename = "/tmp/__reallocation_file_test";
	int fd = open(filename, O_CREAT | O_RDWR);
	T_QUIET; T_ASSERT_NE_INT(fd, -1, "create test file (errno = %s)", strerror(errno));
	ssize_t count = 0;
	while ((count += write(fd, ((char *)truth_buf) + count, whole_src_size - count)) < whole_src_size) {
	}

	/*
	 * Map the file.
	 */
	void *mapped_file = mmap(NULL, whole_src_size, VM_PROT_READ | VM_PROT_WRITE, MAP_SHARED, fd, 0);
	T_QUIET; T_ASSERT_NE_PTR(
		mapped_file, MAP_FAILED,
		"map test file (errno = %s)", strerror(errno));

	/*
	 * Sanity check the file contains the expected data.
	 */
	for (int i = 0; i < (whole_src_size / sizeof(int)); i++) {
		T_QUIET; T_ASSERT_EQ_INT(
			truth_buf[i], ((int *)mapped_file)[i],
			"file contained unexpected data at index %d (0x%x != 0x%x)",
			i, truth_buf[i], ((int *)mapped_file)[i]);
	}

	/*
	 * Reallocate a chunk of the first mapping.
	 */
	mach_vm_address_t addr_to_reallocate = ((mach_vm_address_t)mapped_file) + PAGE_SIZE;
	mach_vm_address_t destination = 0;
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_reallocate(
		    mach_task_self(),
		    addr_to_reallocate,
		    reallocate_src_size,
		    &destination,
		    reallocate_dst_size,
		    0,
		    VM_REALLOCATE_DEALLOCATE_SOURCE,
		    VM_FLAGS_ANYWHERE), "reallocate middle of file");

	/*
	 * Verify that the original chunk is now unmapped.
	 */
	bool segfault = false;
	MAYBE_SIG__START(SIGSEGV)
	volatile char x = *((char *)addr_to_reallocate);
	(void) x;
	MAYBE_SIG__OCCURED(SIGSEGV);
	segfault = true;
	MAYBE_SIG__END(SIGSEGV);
	T_QUIET; T_ASSERT_TRUE(segfault, "source should not be mapped");

	/*
	 * Verify that the source-portion of the reallocated chunk is file-backed.
	 */
	bool original_chunk_external = addr_has_external_pager(destination);
	T_QUIET; T_ASSERT_TRUE(
		original_chunk_external,
		"reallocated portion of mapped file should have external pager");

	/*
	 * Verify that the expanded-portion of the reallocated chunk is anonymous.
	 */
	bool extended_chunk_external = addr_has_external_pager(destination + PAGE_SIZE);
	T_QUIET; T_ASSERT_FALSE(
		extended_chunk_external,
		"extended portion of mapped file should be anonymous memory");

	/*
	 * Verify that the reallocated chunk contains the correct data.
	 */
	for (int i = 0; i < (PAGE_SIZE / sizeof(int)); i++) {
		T_QUIET; T_ASSERT_EQ_INT(
			truth_buf[(PAGE_SIZE / sizeof(int)) + i], ((int *)(destination))[i],
			"destination contained unexpected data at index %d (0x%x != 0x%x)",
			i, truth_buf[(PAGE_SIZE / sizeof(int)) + i], ((int *)(destination))[i]);
	}

	/*
	 * Verify that the file is unmodified.
	 */
	void *mapped_file_verify = mmap(NULL, whole_src_size, VM_PROT_READ, MAP_SHARED, fd, 0);
	T_QUIET; T_ASSERT_NE_PTR(
		mapped_file_verify, MAP_FAILED,
		"re-map file to verify contents (errno = %s)", strerror(errno));

	for (int i = 0; i < (whole_src_size / sizeof(int)); i++) {
		T_QUIET; T_ASSERT_EQ_INT(
			truth_buf[i], ((int *)mapped_file_verify)[i],
			"file contained unexpected data at index %d (0x%x != 0x%x)",
			i, truth_buf[i], ((int *)mapped_file_verify)[i]);
	}

	/*
	 * Clean up all the mappings we created and close the file.
	 */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(
		munmap(mapped_file_verify, whole_src_size),
		"clean up verification mapping");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(
		munmap((void *)destination, reallocate_dst_size),
		"clean up reallocated mapping");
	size_t beginning_of_source_size = ((uintptr_t)addr_to_reallocate) - ((uintptr_t)mapped_file);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(
		munmap(mapped_file, beginning_of_source_size),
		"clean up beginning of original mapping");
	size_t end_of_source_size = whole_src_size - beginning_of_source_size - reallocate_src_size;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(
		munmap((void *)(addr_to_reallocate + reallocate_src_size), end_of_source_size),
		"clean up end of original mapping");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(close(fd), "close the tmp file");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(remove(filename), "delete the tmp file");
}

T_DECL(reallocation_permanent_mapping_fails,
    "verify that we cannot reallocate a range mapped with a permanent entry")
{
	kern_return_t kr;
	mach_vm_address_t src = 0;
	mach_vm_address_t dst = 0;

	/*
	 * Create a permanent mapping.
	 */
	kr = mach_vm_allocate(
		mach_task_self(),
		&src,
		2 * PAGE_SIZE,
		VM_FLAGS_ANYWHERE | VM_FLAGS_PERMANENT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "create permanent mapping");

	/*
	 * Verify that (out-of-place) reallocation of the permanent mapping fails.
	 */
	kr = mach_vm_reallocate(
		mach_task_self(),
		src,
		PAGE_SIZE,
		&dst,
		2 * PAGE_SIZE,
		0,
		VM_REALLOCATE_DEALLOCATE_SOURCE,
		VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_ERROR(KERN_INVALID_ADDRESS, kr, "reallocation should fail");
}

T_DECL(reallocation_fixed_no_expansion,
    "verify that we can relocate a range to a fixed address without expanding it")
{
	kern_return_t kr;
	mach_vm_address_t src = 0;
	mach_vm_address_t dst = 0;

	/*
	 * Create a mapping.
	 */
	kr = mach_vm_allocate(mach_task_self(), &src, 2 * PAGE_SIZE, VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "create mapping");

	/*
	 * Unmap the second page -- this way we know it's free to relocate into.
	 */
	dst = src + PAGE_SIZE;
	kr = mach_vm_deallocate(mach_task_self(), dst, PAGE_SIZE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "unmap the second page");

	/*
	 * Relocate the mapping by +1 page.
	 */
	dst = src + PAGE_SIZE;
	kr = mach_vm_reallocate(
		mach_task_self(),
		src,
		PAGE_SIZE,
		&dst,
		PAGE_SIZE,
		0,
		VM_REALLOCATE_DEALLOCATE_SOURCE,
		VM_FLAGS_FIXED);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "relocate the source");

	/*
	 * Clean up the mapping.
	 */
	kr = mach_vm_deallocate(mach_task_self(), dst, PAGE_SIZE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "clean up relocated mapping");
}

T_DECL(reallocation_fixed_overwrite_no_expansion,
    "verify that we can (FIXED | OVERWRITE) relocate a range without expanding it")
{
	kern_return_t kr;
	mach_vm_address_t src = 0;
	mach_vm_address_t dst = 0;

	/*
	 * Create a mapping.
	 */
	kr = mach_vm_allocate(mach_task_self(), &src, 2 * PAGE_SIZE, VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "create mapping");

	/*
	 * Overwrite the second page of the mapping with the first page.
	 */
	dst = src + PAGE_SIZE;
	kr = mach_vm_reallocate(
		mach_task_self(),
		src,
		PAGE_SIZE,
		&dst,
		PAGE_SIZE,
		0,
		VM_REALLOCATE_DEALLOCATE_SOURCE,
		VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "relocate the source");

	/*
	 * Clean up the mapping.
	 */
	kr = mach_vm_deallocate(mach_task_self(), dst, PAGE_SIZE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "clean up relocated mapping");
}
