#include <darwintest.h>
#include <darwintest_utils.h>

#include <string.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <mach/vm_region_private.h>
#include <mach/vm_types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <TargetConditionals.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM")
	);

struct child_rc {
	int ret;
	int sig;
};

static struct child_rc
fork_child_test(void (^block)(void))
{
	struct child_rc rc = { };
	pid_t child_pid;

	child_pid = fork();

	if (child_pid == 0) {
		block();
		exit(0);
	}

	T_QUIET; T_ASSERT_POSIX_SUCCESS(child_pid, "fork process");

	/* wait for child process to exit */
	dt_waitpid(child_pid, &rc.ret, &rc.sig, 30);
	return rc;
}

static mach_vm_address_t
get_permanent_mapping(mach_vm_size_t size)
{
	kern_return_t kr;
	mach_vm_address_t addr;

	addr = 0;
	kr = mach_vm_allocate(mach_task_self(), &addr, size,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_PERMANENT);

	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_allocate(%lld, PERMANENT) == %p",
	    size, (void *)addr);

	*(int *)addr = 42;

	kr = mach_vm_protect(mach_task_self(), addr, size, FALSE, VM_PROT_READ);

	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_protect(PERMANENT, READ)");

	T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");

	return addr;
}

T_DECL(permanent_mapping, "check permanent mappings semantics", T_META_TAG_VM_PREFERRED)
{
	mach_vm_size_t size = 1 << 20;
	struct child_rc rc;

	T_LOG("try to bypass permanent mappings with VM_FLAGS_OVERWRITE");
	rc = fork_child_test(^{
		mach_vm_address_t addr, addr2;
		kern_return_t kr2;

		addr = get_permanent_mapping(size);

		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");

		addr2 = addr;
		kr2 = mach_vm_allocate(mach_task_self(), &addr2, size,
		VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);

		/*
		 * because the permanent mapping wasn't removed,
		 * we should get an error.
		 */
		T_ASSERT_MACH_ERROR(kr2, KERN_PROTECTION_FAILURE,
		"mach_vm_allocate(VM_FLAGS_OVERWRITE)");

		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");
	});

	T_LOG("try to bypass permanent mappings with a VM_PROT_COPY mprotect");
	rc = fork_child_test(^{
		kern_return_t kr2;
		mach_vm_address_t addr;

		addr = get_permanent_mapping(size);

		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");

		kr2 = mach_vm_protect(mach_task_self(), addr, size, TRUE,
		VM_PROT_COPY | VM_PROT_DEFAULT);

		/*
		 * because the permanent mapping wasn't removed,
		 * we should get an error.
		 */
		T_ASSERT_MACH_ERROR(kr2, KERN_PROTECTION_FAILURE,
		"mach_vm_protect(VM_PROT_COPY)");

		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");
	});

	T_LOG("try to bypass permanent mappings with a vm_remap");
	rc = fork_child_test(^{
		kern_return_t kr2;
		mach_vm_address_t addr, remap_addr, addr2;
		vm_prot_t cur_prot, max_prot;

		addr = get_permanent_mapping(size);

		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");

		addr2 = 0;
		kr2 = mach_vm_allocate(mach_task_self(), &addr2, size,
		VM_FLAGS_ANYWHERE);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr2, "vm_allocate()");

		remap_addr = addr;
		kr2 = mach_vm_remap(mach_task_self(), &remap_addr, size, 0,
		VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
		mach_task_self(), addr2, TRUE,
		&cur_prot, &max_prot, VM_INHERIT_DEFAULT);

		/*
		 * because the permanent mapping wasn't removed,
		 * we should get an error.
		 */
		T_ASSERT_MACH_ERROR(kr2, KERN_PROTECTION_FAILURE,
		"mach_vm_remap()");

		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");
	});

	T_LOG("try to bypass permanent mappings with a vm_deallocate");
	rc = fork_child_test(^{
		kern_return_t kr2;
		mach_vm_address_t addr;

		addr = get_permanent_mapping(size);

		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");

		kr2 = mach_vm_deallocate(mach_task_self(), addr, size);

		/*
		 * the permanent mapping wasn't removed but was made
		 * inaccessible; we should not get an error.
		 */
		T_ASSERT_MACH_SUCCESS(kr2, "mach_vm_deallocate()");

		/*
		 * because the permanent mapping was neutered,
		 * accessing it should crash.
		 */
		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");
	});
	T_EXPECT_EQ(rc.sig, SIGBUS, "accessing the mapping caused a SIGBUS");
}

T_DECL(vm_tag_describe,
    "test mach_vm_tag_describe()",
    T_META_TAG_VM_PREFERRED)
{
	for (unsigned int i = 0; i <= VM_MEMORY_COUNT; i++) {
		const char *desc = mach_vm_tag_describe(i);
		T_LOG("%i: %s", i, desc);
		T_ASSERT_NOTNULL(desc, "Tag description (%i) is non-null", i);
		T_EXPECT_NE_STR(desc, "", "Tag description (%i) is non-empty", i);
		T_EXPECT_LE(strlen(desc), 24UL, "Tag description must be less than 24 characters");
	}
}


#define ADDRESS_REUSE_ENABLED  0  /* a.k.a. VM_TOGGLE_CLEAR in vm_protos.h */
#define ADDRESS_REUSE_DISABLED 1  /* a.k.a. VM_TOGGLE_SET in vm_protos.h */

static int
toggle_address_reuse_sysctl(
	int    *old_value,
	size_t *old_size,
	int    *new_value,
	size_t  new_size)
{
	return sysctlbyname("debug.toggle_address_reuse", old_value, old_size, new_value, new_size);
}

/*
 * Gets the old address-reuse state in *old_enabled_or_null.
 * Pass old_enabled_or_null = NULL to not get the old value.
 * Then sets the address-reuse state to *new_enabled_or_null.
 * Pass new_enabled_or_null = NULL to not set a new value.
 */
static void
get_then_set_address_reuse_enabled(
	bool       * const old_enabled_or_null,
	bool const * const new_enabled_or_null)
{
	int old_value = 42;
	size_t old_size = sizeof(old_value);
	int *old_value_ptr;
	size_t *old_size_ptr;

	if (old_enabled_or_null != NULL) {
		old_value_ptr = &old_value;
		old_size_ptr = &old_size;
	} else {
		old_value_ptr = NULL;
		old_size_ptr = NULL;
	}

	int new_value;
	size_t new_size;
	int *new_value_ptr;

	if (new_enabled_or_null != NULL) {
		new_value = *new_enabled_or_null ? ADDRESS_REUSE_ENABLED : ADDRESS_REUSE_DISABLED;
		new_value_ptr = &new_value;
		new_size = sizeof(new_value);
	} else {
		new_value_ptr = NULL;
		new_size = 0;
	}
	int err = toggle_address_reuse_sysctl(old_value_ptr, old_size_ptr, new_value_ptr, new_size);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "get_then_set_address_reuse_enabled");
	if (old_enabled_or_null != NULL) {
		T_QUIET; T_ASSERT_EQ(old_size, sizeof(old_value), "old_size should be sizeof(int)");
		T_QUIET; T_ASSERT_NE(old_value, 42, "old_value should be updated");
		*old_enabled_or_null = old_value == ADDRESS_REUSE_ENABLED;
	}
}

static bool
get_address_reuse_enabled(void)
{
	bool enabled;
	get_then_set_address_reuse_enabled(&enabled, NULL);
#if 1 /* TODO: remove when fixing rdar://158803749 */
	/*
	 * BUG: sysctl get (with no set) always sets address reuse to enabled.
	 * Write the value that we just read to work around that.
	 */
	bool wrong_enabled;
	get_then_set_address_reuse_enabled(&wrong_enabled, &enabled);
	T_QUIET; T_ASSERT_EQ(wrong_enabled, true, "enabled gets forced on (bug)");
#endif
	return enabled;
}

/* the following are macros to get better assert line numbers */

#define assert_address_reuse_enabled()                                  \
	({                                                              \
	        bool _enabled = get_address_reuse_enabled();            \
	        T_QUIET; T_ASSERT_EQ(_enabled, true, "address reuse should be enabled"); \
	})

#define assert_address_reuse_disabled()                                 \
	({                                                              \
	        bool _enabled = get_address_reuse_enabled();            \
	        T_QUIET; T_ASSERT_EQ(_enabled, false, "address reuse should be disabled"); \
	})

#define enable_address_reuse()                                          \
	({                                                              \
	        get_then_set_address_reuse_enabled(NULL, &(bool){true}); \
	        assert_address_reuse_enabled();                         \
	})

#define disable_address_reuse()                                         \
	({                                                              \
	        get_then_set_address_reuse_enabled(NULL, &(bool){false}); \
	        assert_address_reuse_disabled();                        \
	})

#define NUM_ALLOCS 1000
static mach_vm_address_t allocs[NUM_ALLOCS];

static void
alloc_a_lot(void)
{
	for (int i = 0; i < NUM_ALLOCS; i++) {
		kern_return_t kr;
		kr = mach_vm_allocate(mach_task_self(), &allocs[i], PAGE_SIZE, VM_FLAGS_ANYWHERE);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocate a lot %d", i);
	}
}

static void
dealloc_a_lot(void)
{
	for (int i = 0; i < NUM_ALLOCS; i++) {
		kern_return_t kr;
		kr = mach_vm_deallocate(mach_task_self(), allocs[i], PAGE_SIZE);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate a lot %d", i);
		allocs[i] = 0;
	}
}

static mach_vm_address_t saved_allocs[NUM_ALLOCS];

static void
save_allocs(void)
{
	static_assert(sizeof(allocs) == sizeof(saved_allocs));
	static_assert(sizeof(allocs) == NUM_ALLOCS * sizeof(allocs[0]));
	memcpy(saved_allocs, allocs, sizeof(allocs));
}

static bool
allocs_did_reuse_any_saved_address(void)
{
	/* lists should contain no zeros */
	for (int i = 0; i < NUM_ALLOCS; i++) {
		T_QUIET; T_ASSERT_NE(allocs[i], 0ull, "allocs should not have zeros");
		T_QUIET; T_ASSERT_NE(saved_allocs[i], 0ull, "saved_allocs should not have zeros");
	}

	/* check lists for any reused value */
	for (int i = 0; i < NUM_ALLOCS; i++) {
		for (int j = 0; j < NUM_ALLOCS; j++) {
			if (allocs[i] == saved_allocs[j]) {
				return true;
			}
		}
	}
	return false;
}

T_DECL(toggle_address_reuse, "test sysctl debug.toggle_address_reuse a.k.a. vm_toggle_entry_reuse()",
    T_META_TAG_VM_PREFERRED
    )
{
	/* repeated redundant enable-address-reuse, interspersed with allocations */
	assert_address_reuse_enabled();
	enable_address_reuse();
	enable_address_reuse();
	alloc_a_lot();
	enable_address_reuse();
	dealloc_a_lot();
	T_PASS("enable address reuse");

	/* alloc/dealloc/alloc with address reuse enabled should reuse addresses */
	assert_address_reuse_enabled();
	alloc_a_lot();
	save_allocs();
	dealloc_a_lot();
	alloc_a_lot();
	T_ASSERT_EQ(allocs_did_reuse_any_saved_address(), true, "addresses should be reused when enabled");
	dealloc_a_lot();

	/* repeated redundant disable-address-reuse, interspersed with allocations */
	assert_address_reuse_enabled();
	disable_address_reuse();
	disable_address_reuse();
	alloc_a_lot();
	disable_address_reuse();
	dealloc_a_lot();
	T_PASS("disable address reuse");

	/* alloc/dealloc/alloc with address reuse disabled should not reuse addresses */
	assert_address_reuse_disabled();
	alloc_a_lot();
	save_allocs();
	dealloc_a_lot();
	alloc_a_lot();
	T_ASSERT_EQ(allocs_did_reuse_any_saved_address(), false, "addresses should not be reused when disabled");
	dealloc_a_lot();

	/* cycling address reuse allows old addresses to be reused again */
	assert_address_reuse_disabled();
	alloc_a_lot();
	save_allocs();
	enable_address_reuse();
	disable_address_reuse();
	dealloc_a_lot();
	alloc_a_lot();
	T_ASSERT_EQ(allocs_did_reuse_any_saved_address(), true, "addresses should be reused after a cycle through enabled");
	dealloc_a_lot();

	/* alloc/dealloc/alloc with address reuse enabled should reuse addresses, even after it was disabled once */
	/* (hole list never gets re-enabled so we're in the first_free regime now) */
	assert_address_reuse_disabled();
	enable_address_reuse();
	alloc_a_lot();
	save_allocs();
	dealloc_a_lot();
	alloc_a_lot();
	T_ASSERT_EQ(allocs_did_reuse_any_saved_address(), true, "addresses should be reused after re-enabling");
	dealloc_a_lot();

	/* try all four sysctl permutations */
	int old_value;
	size_t old_size;
	int new_value;
	int err;

	/* nop/nop */
	enable_address_reuse();
	err = toggle_address_reuse_sysctl(NULL, NULL, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "toggle_address_reuse(nop/nop)");
	assert_address_reuse_enabled();

	disable_address_reuse();
	err = toggle_address_reuse_sysctl(NULL, NULL, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "toggle_address_reuse(nop/nop)");
#if 1 /* TODO: remove when fixing rdar://158803749 */
	assert_address_reuse_enabled(); /* BUG, see get_address_reuse_enabled() above */
#else
	assert_address_reuse_disabled();
#endif
	T_PASS("sysctl nop/nop");

	/* get/nop */
	disable_address_reuse();
	old_value = 42;
	old_size = sizeof(old_value);
	err = toggle_address_reuse_sysctl(&old_value, &old_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "toggle_address_reuse(get/nop)");
	T_QUIET; T_ASSERT_EQ(old_value, ADDRESS_REUSE_DISABLED, "get/nop old value");
	T_QUIET; T_ASSERT_EQ(old_size, sizeof(old_value), "get/nop old size");
#if 1 /* TODO: remove when fixing rdar://158803749 */
	assert_address_reuse_enabled(); /* BUG, see get_address_reuse_enabled() above */
#else
	assert_address_reuse_disabled();
#endif
	T_PASS("sysctl get/nop");

	/* nop/set */
	enable_address_reuse();
	new_value = ADDRESS_REUSE_DISABLED;
	err = toggle_address_reuse_sysctl(NULL, NULL, &new_value, sizeof(new_value));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "toggle_address_reuse(nop/set)");
	assert_address_reuse_disabled();
	T_PASS("sysctl nop/set");

	/* get/set */
	enable_address_reuse();
	old_value = 42;
	old_size = sizeof(old_value);
	new_value = ADDRESS_REUSE_DISABLED;
	err = toggle_address_reuse_sysctl(&old_value, &old_size, &new_value, sizeof(new_value));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "toggle_address_reuse(get/set)");
	T_QUIET; T_ASSERT_EQ(old_value, ADDRESS_REUSE_ENABLED, "get/set old value");
	T_QUIET; T_ASSERT_EQ(old_size, sizeof(old_value), "get/set old size");
	assert_address_reuse_disabled();
	T_PASS("sysctl get/set");

	/* try an invalid new value */
	enable_address_reuse();
	old_value = 42;
	old_size = sizeof(old_value);
	new_value = 42;
	err = toggle_address_reuse_sysctl(&old_value, &old_size, &new_value, sizeof(new_value));
#if 1 /* TODO: remove when fixing rdar://158806524 */
	int expected_err = KERN_INVALID_ARGUMENT;  /* BUG, should be EINVAL */
#else
	int expected_err = EINVAL;
#endif
	T_QUIET; T_ASSERT_POSIX_FAILURE(err, expected_err, "toggle_address_reuse(get/invalid-set)");
	T_QUIET; T_ASSERT_EQ(old_value, ADDRESS_REUSE_ENABLED, "get/invalid-set old value");
	T_QUIET; T_ASSERT_EQ(old_size, sizeof(old_value), "get/invalid-set old size");
	assert_address_reuse_enabled();
	T_PASS("sysctl get/invalid-set");

	/* exhaust the address space */
	disable_address_reuse();
	int allocated = 0;
	mach_vm_address_t max_addr = 0;
	while (true) {
		/*
		 * We repeatedly allocate and free large allocations.
		 * With address reuse disabled this should eventually
		 * run out of address space and fail with KERN_NO_SPACE.
		 */
		mach_vm_size_t size = 512 * 1024 * 1024; /* 512 MB */
		mach_vm_address_t addr = 0;
		kern_return_t kr;

		kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE);
		if (kr != KERN_SUCCESS) {
			T_ASSERT_GT(allocated, 0, "should have allocated at least once "
			    "while exhausting the address space (did allocate %d times)", allocated);
			T_ASSERT_MACH_ERROR(kr, KERN_NO_SPACE, "should fail to allocate eventually");
			break;
		}
		T_QUIET; T_ASSERT_GT(addr, max_addr, "should not reuse while exhausting the address space");
		max_addr = addr;
		allocated++;

		kr = mach_vm_deallocate(mach_task_self(), addr, size);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate");
	}
}
