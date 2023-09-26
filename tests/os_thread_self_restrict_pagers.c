#include <darwintest.h>
#include <darwintest_perf.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.vm"));

#include <machine/cpu_capabilities.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <libkern/OSCacheControl.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/sysctl.h>

#include <mach/vm_param.h>
#include <pthread.h>

#include <os/thread_self_restrict.h>

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/task.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#if defined(__arm64__)
/* PAGE_SIZE on ARM64 is an expression derived from a non-const global variable */
#define PAD_SIZE        PAGE_MAX_SIZE
#else
#define PAD_SIZE        PAGE_MIN_SIZE
#endif

/* Enumerations */
typedef enum _access_type {
	ACCESS_READ,
	ACCESS_WRITE,
} access_type_t;

typedef enum _fault_strategy {
	FAULT_STRAT_NONE,
	FAULT_STRAT_RW_TPRO,
} fault_strategy_t;

/* Structures */
typedef struct {
	uint64_t fault_count;
	fault_strategy_t fault_strategy;
	bool fault_expected;
} fault_state_t;

/* Globals */
static bool key_created = false;
static pthread_key_t fault_state_key;

/*
 * The pager will only map entries with TPRO if we need to perform fixups.
 * Otherwise it really is const. Ensure we forge a struct that will require
 * dynamic rebasing.
 */
typedef struct {
	void *reloc;
	uint32_t magic;
	char bytes[PAD_SIZE - 12];
} const_page_t;

typedef struct {
	const_page_t one;
	const_page_t two;
	char ro[PAD_SIZE];
} const_state_t;

#define MAGIC(state) (void *)&state->magic

/*
 * Force known data into our __DATA_CONST segment. The pager will be responsible
 * for handling the mapping of this.
 */
__attribute__((section("__DATA_CONST,__pager")))
__attribute__((aligned(PAD_SIZE)))
static const_state_t pager_state = {
	.one.reloc = &pager_state,
	.two.reloc = &pager_state,
	.one.magic = 0x41414141,
	.two.magic = 0x41414141,
	.ro = "CCCC"
};

/* Allocate a fault_state_t, and associate it with the current thread. */
static fault_state_t *
fault_state_create(void)
{
	fault_state_t * fault_state = malloc(sizeof(fault_state_t));

	if (fault_state) {
		fault_state->fault_count = 0;
		fault_state->fault_strategy = FAULT_STRAT_NONE;
		fault_state->fault_expected = false;

		if (pthread_setspecific(fault_state_key, fault_state)) {
			free(fault_state);
			fault_state = NULL;
		}
	}

	return fault_state;
}

/* Disassociate the given fault state from the current thread, and destroy it. */
static void
fault_state_destroy(void * fault_state)
{
	if (fault_state == NULL) {
		T_ASSERT_FAIL("Attempted to fault_state_destroy NULL");
	}

	free(fault_state);
}

/*
 * A signal handler that attempts to resolve anticipated faults through use of
 * the os_thread_self_restrict_rwx functions.
 */
static void
access_failed_handler(int signum)
{
	fault_state_t * fault_state;

	/* This handler should ONLY handle SIGBUS. */
	if (signum != SIGBUS) {
		T_ASSERT_FAIL("Unexpected signal sent to handler");
	}

	if (!(fault_state = pthread_getspecific(fault_state_key))) {
		T_ASSERT_FAIL("Failed to retrieve fault state");
	}

	if (!(fault_state->fault_expected)) {
		T_ASSERT_FAIL("Unexpected fault taken");
	}

	/* We should not see a second fault. */
	fault_state->fault_expected = false;

	switch (fault_state->fault_strategy) {
	case FAULT_STRAT_NONE:
		T_ASSERT_FAIL("No fault strategy");

		/* Just in case we try to do something different. */
		break;
	case FAULT_STRAT_RW_TPRO:
		os_thread_self_restrict_tpro_to_rw();
		break;
	}

	fault_state->fault_count++;
}

/*
 * Attempt the specified access; if the access faults, this will return true;
 * otherwise, it will return false.
 */
static bool
does_access_fault(access_type_t access_type, void * addr, uint32_t value)
{
	uint64_t old_fault_count;
	uint64_t new_fault_count;

	fault_state_t * fault_state;

	struct sigaction old_action; /* Save area for any existing action. */
	struct sigaction new_action; /* The action we wish to install for SIGBUS. */

	bool retval = false;

	new_action.sa_handler = access_failed_handler; /* A handler for write failures. */
	new_action.sa_mask    = 0;                     /* Don't modify the mask. */
	new_action.sa_flags   = 0;                     /* Flags?  Who needs those? */

	if (addr == NULL) {
		T_ASSERT_FAIL("Access attempted against NULL");
	}

	if (!(fault_state = pthread_getspecific(fault_state_key))) {
		T_ASSERT_FAIL("Failed to retrieve fault state");
	}

	old_fault_count = fault_state->fault_count;

	/* Install a handler so that we can catch SIGBUS. */
	sigaction(SIGBUS, &new_action, &old_action);

	/* Perform the requested operation. */
	switch (access_type) {
	case ACCESS_READ:
		fault_state->fault_strategy = FAULT_STRAT_RW_TPRO;
		fault_state->fault_expected = true;

		__sync_synchronize();

#if defined(__arm64__)
		uint8_t a = *((volatile uint8_t *)addr);
#endif
		__sync_synchronize();

		fault_state->fault_expected = false;
		fault_state->fault_strategy = FAULT_STRAT_NONE;

		break;

	case ACCESS_WRITE:
		fault_state->fault_strategy = FAULT_STRAT_RW_TPRO;
		fault_state->fault_expected = true;

		__sync_synchronize();

		*((volatile uint32_t *)addr) = value;

		__sync_synchronize();

		fault_state->fault_expected = false;
		fault_state->fault_strategy = FAULT_STRAT_NONE;

		break;
	}

	/* Restore the old SIGBUS handler. */
	sigaction(SIGBUS, &old_action, NULL);

	new_fault_count = fault_state->fault_count;

	if (new_fault_count > old_fault_count) {
		/* Indicate that we took a fault. */
		retval = true;
	}

	return retval;
}

static bool
does_read_fault(void * addr)
{
	return does_access_fault(ACCESS_READ, addr, 0);
}

static bool
does_write_fault(void * addr, uint32_t value)
{
	return does_access_fault(ACCESS_WRITE, addr, value);
}

static bool
has_pager_support(void)
{
	uint32_t enabled = false;
	size_t output_size = sizeof(enabled);

	(void)sysctlbyname("vm.pmap_tpro_pagers",
	    &enabled, &output_size, NULL, 0);
	return enabled;
}

static void
cleanup(void)
{
	fault_state_t * fault_state;

	if (!(fault_state = pthread_getspecific(fault_state_key))) {
		T_ASSERT_FAIL("Failed to retrieve fault state");

		T_ASSERT_POSIX_ZERO(pthread_setspecific(fault_state_key, NULL), "Remove fault_state");
		fault_state_destroy(fault_state);
	}

	if (key_created) {
		T_ASSERT_POSIX_ZERO(pthread_key_delete(fault_state_key), "Delete fault state key");
	}

	return;
}

static void
thread_self_restrict_test(void (^test)(void))
{
	int err = 0;

	T_SETUPBEGIN;
	T_ATEND(cleanup);

	/* Set up the necessary state for the test. */
	err = pthread_key_create(&fault_state_key, fault_state_destroy);
	T_ASSERT_POSIX_ZERO(err, 0, "Create pthread key");
	key_created = true;

	T_ASSERT_NOTNULL(fault_state_create(), "Create fault state");
	T_SETUPEND;

	test();
}

static void
fork_child_test(const_page_t *state)
{
	pid_t pid;
	int statloc;

	pid = fork();
	if (pid == 0) {
		T_EXPECT_EQ(state->magic, 0x45454545, "Expected magic on fork");

		os_thread_self_restrict_tpro_to_rw();
		T_EXPECT_EQ(os_thread_self_restrict_tpro_is_writable(), true, "TPRO region configured as read-write in child");
		T_EXPECT_EQ(does_write_fault((void *)&state->bytes, 0x47474747), 0, "write to pager backed memory in child (no fault)");
		T_EXPECT_EQ(does_write_fault(MAGIC(state), 0x46464646), 0, "write to pager backed memory in child (no fault)");
		exit(0);
	}

	if (pid < 0) {
		T_ASSERT_POSIX_SUCCESS(pid, "fork");
	}

	waitpid(pid, &statloc, 0);
}

static void
pager_test(const_page_t *state)
{
	kern_return_t kr;
	uint32_t pre;
	vm_prot_t curprot, maxprot;
	mach_vm_address_t addr = 0;
	const_page_t *copy_state = NULL;
	mach_port_t cow_port = MACH_PORT_NULL;
	memory_object_size_t me_size = PAGE_SIZE;

	/*
	 * Validate our initial status quo. TPRO permissions should be RO,
	 * so we should be able to read from our pager backed mapping but
	 * should fault when trying to write to it.
	 */
	T_EXPECT_EQ(os_thread_self_restrict_tpro_is_writable(), false, "TPRO region starts read-only");
	T_EXPECT_EQ(does_read_fault(MAGIC(state)), 0, "read from pager backed memory");
	T_EXPECT_EQ(does_write_fault(MAGIC(state), 0x43434343), 1, "write to pager backed memory (detect fault)");

	/*
	 * Toggle permissions to RW and attempt a write. We should succeed.
	 */
	os_thread_self_restrict_tpro_to_rw();
	T_EXPECT_EQ(os_thread_self_restrict_tpro_is_writable(), true, "TPRO region configured as read-write");
	T_EXPECT_EQ(does_write_fault(MAGIC(state), 0x44444444), 0, "write to pager backed memory (no fault)");

	/*
	 * Toggle permissions to RO and attempt a write. We should detect
	 * the fault
	 */
	os_thread_self_restrict_tpro_to_ro();
	T_EXPECT_EQ(does_write_fault(MAGIC(state), 0x45454545), 1, "write to pager backed memory (detect fault)");

	/*
	 * Fork a child process and ensure that writes into the pager backed
	 * regions are not observed by the parent. They should now be COW.
	 */
	pre = state->magic;
	fork_child_test(state);
	T_EXPECT_EQ(pre, state->magic, "write from child should not be observed");

	/*
	 * Ensure that if we remap the target region in a shared manner that we
	 * inherit TPRO. Remapping should be successful but we still rely on
	 * TPRO permissions to toggle r--/rw-
	 */
	kr = mach_vm_remap(mach_task_self(),
	    &addr,
	    PAGE_SIZE,
	    0,                /* mask */
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    (mach_vm_address_t)state,
	    FALSE,                /* copy */
	    &curprot,
	    &maxprot,
	    VM_INHERIT_DEFAULT);
	T_EXPECT_POSIX_SUCCESS(kr, "mach_vm_remap(SHARED)");
	copy_state = (const_page_t *)addr;

	os_thread_self_restrict_tpro_to_ro();
	T_EXPECT_EQ(os_thread_self_restrict_tpro_is_writable(), false, "TPRO configured as read-only");
	T_EXPECT_EQ(curprot, VM_PROT_READ, "TPRO region should be VM_PROT_READ");
	T_EXPECT_EQ(does_write_fault(MAGIC(copy_state), 0x46464646), 1, "write to remapped region (detect fault)");
	os_thread_self_restrict_tpro_to_rw();
	T_EXPECT_EQ(does_write_fault(MAGIC(copy_state), 0x46464646), 0, "write to remapped region (no fault)");
	T_EXPECT_EQ(0x46464646, state->magic, "write into copied region should be observed");

	/*
	 * Ensure that if we remap the region that we do not observe writes to
	 * the new copy in __DATA_CONST itself.
	 */
	kr = mach_vm_remap(mach_task_self(),
	    (mach_vm_address_t *)&copy_state,
	    PAGE_SIZE,
	    0,                /* mask */
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    (mach_vm_address_t)state,
	    TRUE,                /* copy */
	    &curprot,
	    &maxprot,
	    VM_INHERIT_DEFAULT);
	T_EXPECT_POSIX_SUCCESS(kr, "mach_vm_remap(COPY)");

	/*
	 * Toggle TPRO RW and write to the new copied region
	 */
	pre = state->magic;
	os_thread_self_restrict_tpro_to_rw();
	T_EXPECT_EQ(os_thread_self_restrict_tpro_is_writable(), true, "TPRO region configured as read-write");
	T_EXPECT_EQ(does_write_fault(MAGIC(copy_state), 0x46464646), 0, "write to pager backed memory (no fault)");
	T_EXPECT_EQ(pre, state->magic, "write into copied region should not be observed");

	/*
	 * Make a memory entry for our target region and attempt to map it in
	 * in a shared fashion. We should succeed but it should transparently
	 * copy the target VM object as extracting TPRO VM entries will fail.
	 * Writes to the new region should therefore not be observed.
	 */
	me_size = PAGE_SIZE;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &me_size,
	    (mach_vm_address_t)state,
	    MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE,
	    &cow_port,
	    MACH_PORT_NULL);
	T_EXPECT_POSIX_SUCCESS(kr, "mach_make_memory_entry_64(MAP_MEM_VM_SHARE)");

	pre = state->magic;
	T_EXPECT_EQ(does_write_fault(MAGIC(copy_state), 0x48484849), 0, "write to mapped copy region (no fault)");
	T_EXPECT_EQ(pre, state->magic, "write into copied region should not be observed");

	copy_state = NULL;
	kr = mach_vm_map(mach_task_self(),
	    (mach_vm_address_t *)&copy_state,
	    PAGE_SIZE,
	    0,              /* mask */
	    VM_FLAGS_ANYWHERE,
	    cow_port,
	    0,              /* offset */
	    TRUE,           /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_EXPECT_POSIX_SUCCESS(kr, "mach_vm_map(cow_port)");

	/*
	 * Pages of the copy will no longer be mapped in as TPRO. Both
	 * read/writes should work even with TPRO toggled RO.
	 */
	pre = state->magic;
	os_thread_self_restrict_tpro_to_ro();
	T_EXPECT_EQ(does_write_fault(MAGIC(copy_state), 0x48484848), 0, "write to mapped copy region (no fault)");
	T_EXPECT_EQ(pre, state->magic, "write into copied region should not be observed");

	/*
	 * We've explored a number of ways to perform copies on the target
	 * objects in __DATA_CONST. Our first target page (&pager_state.one)
	 * should now be marked RO without TPRO permissions to handle any
	 * incoming write faults. Write to it directly again to ensure we
	 * fault back in with TPRO permissions.
	 */
	os_thread_self_restrict_tpro_to_ro();
	T_EXPECT_EQ(does_write_fault(MAGIC(state), 0x49494949), 1, "write to pager backed memory (detect fault)");
	os_thread_self_restrict_tpro_to_rw();
	T_EXPECT_EQ(does_write_fault(MAGIC(state), 0x4a4a4a4a), 0, "write to pager backed memory (no fault)");

	/*
	 * Now we attempt to have the page paged out. On systems which support the
	 * compressor, we'll get paged out/compressed. On fault we should
	 * be pmapped back in with TPRO permissions.
	 */
	mach_vm_behavior_set(mach_task_self(), (mach_vm_address_t)state, PAGE_SIZE, VM_BEHAVIOR_PAGEOUT);

	/*
	 * Can verify in debugger at this point that page(s) have been
	 * paged out. If compressor pager is available the page should
	 * not be resident and compressor pager should be tied to the
	 * top level VM object.
	 */
	os_thread_self_restrict_tpro_to_ro();
	T_EXPECT_EQ(does_write_fault(MAGIC(state), 0x49494949), 1, "write to pager backed memory after pageout (detect fault)");
	os_thread_self_restrict_tpro_to_rw();
	T_EXPECT_EQ(does_write_fault(MAGIC(state), 0x4a4a4a4a), 0, "write to pager backed memory after pageout (no fault)");

	/*
	 * Try and reprotect the region. We should fail
	 */
	kr = vm_protect(mach_task_self(), (mach_vm_address_t)state, PAGE_SIZE, FALSE, VM_PROT_DEFAULT);
	T_EXPECT_POSIX_ERROR(kr, KERN_PROTECTION_FAILURE, "vm_protect(RW) should fail");

	os_thread_self_restrict_tpro_to_ro();
}

T_DECL(thread_self_restrict_pagers,
    "Verify that the TPRO pager interfaces work correctly")
{
#if __arm64__
	/* Check to see that we support the necessary hardware features. */
	if (!os_thread_self_restrict_tpro_is_supported() || !has_pager_support()) {
		T_SKIP("no hardware TPRO support enabled on this system");
	}

	thread_self_restrict_test(^{
		pager_test(&pager_state.one);

		/*
		 * Ensure that touching the second pager supported page exhibits
		 * identical behaviour in order to validate the transitions between
		 * VM entry & copy object chains.
		 */
		pager_test(&pager_state.two);

		/*
		 * Try and write to a normal __DATA_CONST page that isn't backed by
		 * the dyld pager. The kernel will have mapped this directly but
		 * should still maintain TPRO protection.
		 */
		os_thread_self_restrict_tpro_to_ro();
		T_EXPECT_EQ(does_write_fault(&pager_state.ro[0], 0x41414141), 1, "write to __DATA_CONST should succeed (no fault)");
		os_thread_self_restrict_tpro_to_rw();
		T_EXPECT_EQ(does_write_fault(&pager_state.ro[0], 0x41414141), 0, "write to __DATA_CONST should fail (detect fault)");
	});
#else
	T_SKIP("thread_self_restrict_pagers not supported on this system");
#endif /* __arm64__ */
}
