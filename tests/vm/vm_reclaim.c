#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_reclaim_private.h>
#include <mach-o/dyld.h>
#include <os/atomic_private.h>
#include <signal.h>
#include <spawn.h>
#include <spawn_private.h>
#include <time.h>
#include <unistd.h>

#include <darwintest.h>
#include <darwintest_multiprocess.h>
#include <darwintest_utils.h>

#include <Kernel/kern/ledger.h>
extern int ledger(int cmd, caddr_t arg1, caddr_t arg2, caddr_t arg3);

#include "memorystatus_assertion_helpers.h"

#if TARGET_OS_IOS && !TARGET_OS_VISION
// Some of the unit tests test deferred deallocations.
// For these we need to set a sufficiently large reclaim threshold
// to ensure their buffers aren't freed prematurely.
#define T_META_VM_RECLAIM_ENABLED T_META_SYSCTL_INT("vm.reclaim.max_threshold=268435456")
#define T_META_VM_RECLAIM_DISABLED T_META_SYSCTL_INT("vm.reclaim.max_threshold=0")
#else // !TARGET_OS_IOS
#define T_META_VM_RECLAIM_ENABLED T_META_SYSCTL_INT("vm.reclaim.enabled=1")
#define T_META_VM_RECLAIM_DISABLED T_META_SYSCTL_INT("vm.reclaim.enabled=0")
#endif // TARGET_OS_IOS

#define MiB(x) (x << 20)

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm_reclaim"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("performance"),
	T_META_OWNER("jarrad"),
	// Ensure we don't conflict with libmalloc's reclaim buffer
	T_META_ENVVAR("MallocDeferredReclaim=0"),
	T_META_RUN_CONCURRENTLY(false),
	T_META_CHECK_LEAKS(false)
	);

static mach_vm_reclaim_ring_t
ringbuffer_init(void)
{
	mach_vm_reclaim_ring_t ringbuffer = NULL;
	mach_vm_reclaim_count_t len = mach_vm_reclaim_round_capacity(1);
	mach_vm_reclaim_count_t max_len = len;
	kern_return_t kr = mach_vm_reclaim_ring_allocate(&ringbuffer, len, max_len);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ring_allocate()");
	return ringbuffer;
}

T_DECL(vm_reclaim_init, "Set up and tear down a reclaim buffer",
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	mach_vm_reclaim_ring_t ringbuffer = ringbuffer_init();
	T_ASSERT_NOTNULL(ringbuffer, "ringbuffer is allocated");
	T_EXPECT_EQ(os_atomic_load(&ringbuffer->indices.head, relaxed), 0ull, "head is zeroed");
	T_EXPECT_EQ(os_atomic_load(&ringbuffer->indices.busy, relaxed), 0ull, "busy is zeroed");
	T_EXPECT_EQ(os_atomic_load(&ringbuffer->indices.tail, relaxed), 0ull, "tail is zeroed");
	size_t expected_len = (vm_page_size - offsetof(struct mach_vm_reclaim_ring_s, entries)) /
	    sizeof(struct mach_vm_reclaim_entry_s);
	T_ASSERT_EQ((size_t)ringbuffer->len, expected_len, "length is set correctly");
	for (unsigned i = 0; i < ringbuffer->len; i++) {
		mach_vm_reclaim_entry_t entry = &ringbuffer->entries[i];
		T_QUIET; T_EXPECT_EQ(entry->address, 0ull, "address is zeroed");
		T_QUIET; T_EXPECT_EQ(entry->size, 0u, "size is zeroed");
		T_QUIET; T_EXPECT_EQ(entry->behavior, 0, "behavior is zeroed");
	}
}

T_DECL(vm_reclaim_init_fails_when_disabled,
    "Initializing a ring buffer on a system with vm_reclaim disabled should fail",
    T_META_VM_RECLAIM_DISABLED, T_META_TAG_VM_PREFERRED)
{
	mach_vm_reclaim_ring_t ringbuffer;
	kern_return_t kr = mach_vm_reclaim_ring_allocate(&ringbuffer, 1, 1);
	T_EXPECT_MACH_ERROR(kr, VM_RECLAIM_NOT_SUPPORTED, "mach_vm_reclaim_ring_allocate()");
}

static bool
try_cancel(mach_vm_reclaim_ring_t ringbuffer, mach_vm_reclaim_id_t id, mach_vm_address_t addr, mach_vm_size_t size, mach_vm_reclaim_action_t behavior)
{
	bool update_accounting;
	mach_vm_reclaim_state_t state;
	kern_return_t kr;
	kr = mach_vm_reclaim_try_cancel(ringbuffer, id, addr, size, behavior, &state, &update_accounting);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_try_cancel()");
	if (update_accounting) {
		kern_return_t tmp_kr = mach_vm_reclaim_update_kernel_accounting(ringbuffer);
		T_QUIET; T_ASSERT_MACH_SUCCESS(tmp_kr, "mach_vm_reclaim_update_kernel_accounting()");
	}
	return mach_vm_reclaim_is_reusable(state);
}

/*
 * Allocate a buffer of the given size, write val to each byte, and free it via a deferred free call.
 */
static mach_vm_reclaim_id_t
allocate_and_defer_free(size_t size, mach_vm_reclaim_ring_t ringbuffer,
    unsigned char val, mach_vm_reclaim_action_t behavior,
    mach_vm_address_t *addr /* OUT */)
{
	kern_return_t kr = mach_vm_map(mach_task_self(), addr, size, 0, VM_FLAGS_ANYWHERE, MEMORY_OBJECT_NULL, 0, FALSE, VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
	bool should_update_kernel_accounting = false;
	mach_vm_reclaim_id_t id = VM_RECLAIM_ID_NULL;
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_map");

	memset((void *) *addr, val, size);

	kr = mach_vm_reclaim_try_enter(ringbuffer, *addr, size, behavior, &id, &should_update_kernel_accounting);
	if (should_update_kernel_accounting) {
		kr = mach_vm_reclaim_update_kernel_accounting(ringbuffer);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_update_kernel_accounting()");
	}
	return id;
}

static mach_vm_reclaim_id_t
allocate_and_defer_deallocate(size_t size, mach_vm_reclaim_ring_t ringbuffer, unsigned char val, mach_vm_address_t *addr /* OUT */)
{
	return allocate_and_defer_free(size, ringbuffer, val, VM_RECLAIM_DEALLOCATE, addr);
}

T_DECL(vm_reclaim_single_entry, "Place a single entry in the buffer and call sync",
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	static const size_t kAllocationSize = (1UL << 20); // 1MB
	mach_vm_address_t addr;
	mach_vm_reclaim_ring_t ringbuffer = ringbuffer_init();

	mach_vm_reclaim_id_t idx = allocate_and_defer_deallocate(kAllocationSize, ringbuffer, 1, &addr);
	T_QUIET; T_ASSERT_EQ(idx, 0ULL, "Entry placed at start of buffer");
	mach_vm_reclaim_ring_flush(ringbuffer, 1);
}

static pid_t
spawn_helper(char *helper)
{
	char **launch_tool_args;
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size;
	pid_t child_pid;

	testpath_buf_size = sizeof(testpath);
	int ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "_NSGetExecutablePath");
	T_LOG("Executable path: %s", testpath);
	launch_tool_args = (char *[]){
		testpath,
		"-n",
		helper,
		NULL
	};

	/* Spawn the child process. */
	ret = dt_launch_tool(&child_pid, launch_tool_args, false, NULL, NULL);
	if (ret != 0) {
		T_LOG("dt_launch tool returned %d with error code %d", ret, errno);
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(child_pid, "dt_launch_tool");

	return child_pid;
}

static int
spawn_helper_and_wait_for_exit(char *helper)
{
	int status;
	pid_t child_pid, rc;

	child_pid = spawn_helper(helper);
	rc = waitpid(child_pid, &status, 0);
	T_QUIET; T_ASSERT_EQ(rc, child_pid, "waitpid");
	return status;
}

/*
 * Returns true iff every entry in buffer is expected.
 */
static bool
check_buffer(mach_vm_address_t addr, size_t size, unsigned char expected)
{
	unsigned char *buffer = (unsigned char *) addr;
	for (size_t i = 0; i < size; i++) {
		if (buffer[i] != expected) {
			return false;
		}
	}
	return true;
}

/*
 * Read every byte of a buffer to ensure re-usability
 */
static void
read_buffer(mach_vm_address_t addr, size_t size)
{
	volatile uint8_t byte;
	uint8_t *buffer = (uint8_t *)addr;
	for (size_t i = 0; i < size; i++) {
		byte = buffer[i];
	}
}

/*
 * Check that the given (freed) buffer has changed.
 * This will likely crash, but if we make it through the entire buffer then segfault on purpose.
 */
static void
assert_buffer_has_changed_and_crash(mach_vm_address_t addr, size_t size, unsigned char expected)
{
	/*
	 * mach_vm_reclaim_ring_flush should have ensured the buffer was freed.
	 * Two cases:
	 * 1. The buffer is still free (touching it causes a crash)
	 * 2. The address range was re-allocated by some other library in process.
	 * #1 is far more likely. But if #2 happened, the buffer shouldn't be filled
	 * with the value we wrote to it. So scan the buffer. If we segfault it's case #1
	 * and if we see another value it's case #2.
	 */
	bool changed = !check_buffer(addr, size, expected);
	T_QUIET; T_ASSERT_TRUE(changed, "buffer was re-allocated");
	/* Case #2. Force a segfault so the parent sees that we crashed. */
	*(volatile int *) 0 = 1;

	T_FAIL("Test did not crash when dereferencing NULL");
}

static void
reuse_reclaimed_entry(mach_vm_reclaim_action_t behavior)
{
	kern_return_t kr;
	static const size_t kAllocationSize = (1UL << 20); // 1MB
	mach_vm_address_t addr;
	static const unsigned char kValue = 220;

	mach_vm_reclaim_ring_t ringbuffer = ringbuffer_init();

	mach_vm_reclaim_id_t idx = allocate_and_defer_free(kAllocationSize, ringbuffer, kValue, behavior, &addr);
	T_QUIET; T_ASSERT_EQ(idx, 0ULL, "Entry placed at start of buffer");
	kr = mach_vm_reclaim_ring_flush(ringbuffer, 10);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ring_flush");
	bool usable = try_cancel(ringbuffer, idx, addr, kAllocationSize, behavior);
	switch (behavior) {
	case VM_RECLAIM_DEALLOCATE:
		T_EXPECT_FALSE(usable, "reclaimed entry is not re-usable");
		assert_buffer_has_changed_and_crash(addr, kAllocationSize, kValue);
		break;
	case VM_RECLAIM_FREE:
		T_EXPECT_TRUE(usable, "reclaimed REUSABLE entry is re-usable");
		read_buffer(addr, kAllocationSize);
		T_PASS("Freed buffer re-used successfully");
		break;
	default:
		T_FAIL("Unexpected reclaim behavior %d", behavior);
	}
}

T_HELPER_DECL(reuse_freed_entry_dealloc,
    "defer free (dealloc), sync, and try to use entry")
{
	reuse_reclaimed_entry(VM_RECLAIM_DEALLOCATE);
}

T_HELPER_DECL(reuse_freed_entry_reusable,
    "defer free (reusable), sync, and try to use entry")
{
	reuse_reclaimed_entry(VM_RECLAIM_FREE);
}

T_DECL(vm_reclaim_single_entry_verify_free, "Place a single entry in the buffer and call sync",
    T_META_IGNORECRASHES(".*vm_reclaim_single_entry_verify_free.*"),
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	int status = spawn_helper_and_wait_for_exit("reuse_freed_entry_dealloc");
	T_QUIET; T_ASSERT_TRUE(WIFSIGNALED(status), "Test process crashed.");
	T_QUIET; T_ASSERT_EQ(WTERMSIG(status), SIGSEGV, "Test process crashed with segmentation fault.");
}

T_DECL(vm_reclaim_single_entry_reusable,
    "Reclaim a reusable entry and verify re-use is legal",
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	int status = spawn_helper_and_wait_for_exit("reuse_freed_entry_reusable");
	T_QUIET; T_ASSERT_TRUE(WIFEXITED(status), "Test process exited.");
	T_QUIET; T_ASSERT_EQ(WEXITSTATUS(status), 0, "Test process exited cleanly.");
}

static void
allocate_and_suspend(char *const *argv, bool free_buffer, bool double_free)
{
	kern_return_t kr;
	static const mach_vm_reclaim_count_t kAllocationSize = (1UL << 20); // 1MB
	mach_vm_address_t addr = 0;
	bool should_update_kernel_accounting = false;
	mach_vm_reclaim_ring_t ringbuffer = ringbuffer_init();

	const mach_vm_reclaim_count_t kNumEntries = (mach_vm_reclaim_count_t)atoi(argv[0]);
	mach_vm_reclaim_count_t capacity;
	kr = mach_vm_reclaim_ring_capacity(ringbuffer, &capacity);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ring_capacity()");
	T_QUIET; T_ASSERT_LT(kNumEntries, capacity, "Test does not fill up ringbuffer");

	T_LOG("allocate_and_suspend: Allocating and freeing %u entries...", kNumEntries);
	for (size_t i = 0; i < kNumEntries; i++) {
		addr = 0;
		mach_vm_reclaim_id_t idx = allocate_and_defer_deallocate(kAllocationSize, ringbuffer, (unsigned char) i, &addr);
		T_QUIET; T_ASSERT_EQ(idx, (mach_vm_reclaim_id_t)i, "idx is correct");
		T_LOG("allocate_and_suspend: Allocated and deferred 0x%llx", addr);
	}

	if (double_free) {
		// Double free the last entry
		mach_vm_reclaim_id_t id = VM_RECLAIM_ID_NULL;
		kr = mach_vm_reclaim_try_enter(ringbuffer, addr, kAllocationSize, VM_RECLAIM_DEALLOCATE, &id, &should_update_kernel_accounting);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_try_enter");
	}

	if (free_buffer) {
		mach_vm_size_t buffer_size = (size_t)capacity *
		    sizeof(struct mach_vm_reclaim_entry_s) + offsetof(struct mach_vm_reclaim_ring_s, entries);
		kr = mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)ringbuffer, buffer_size);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate");
	}

	T_LOG("allocate_and_suspend: Signalling parent");
	// Signal to our parent to suspend us
	if (kill(getppid(), SIGUSR1) != 0) {
		T_LOG("Unable to signal to parent process!");
		exit(1);
	}

	T_LOG("allocate_and_suspend: Spinning");
	while (1) {
		;
	}
	T_ASSERT_FAIL("notreached");
}

T_HELPER_DECL(allocate_and_suspend,
    "defer free, and signal parent to suspend")
{
	allocate_and_suspend(argv, false, false);
}

static void
resume_and_kill_proc(pid_t pid)
{
	int ret = pid_resume(pid);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "proc resumed after freeze");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(kill(pid, SIGKILL), "Killed process");
}

static void
wait_for_pid_to_be_drained(pid_t child_pid)
{
	int val = child_pid;
	int ret;
	size_t len = sizeof(val);
	ret = sysctlbyname("vm.reclaim.wait_for_pid", NULL, NULL, &val, len);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "vm.reclaim.wait_for_pid");
}

static size_t
ledger_phys_footprint_index(size_t *num_entries)
{
	struct ledger_info li;
	struct ledger_template_info *templateInfo = NULL;
	int ret;
	size_t i, footprint_index;
	bool found = false;

	ret = ledger(LEDGER_INFO, (caddr_t)(uintptr_t)getpid(), (caddr_t)&li, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "ledger(LEDGER_INFO)");

	T_QUIET; T_ASSERT_GT(li.li_entries, (int64_t) 0, "num ledger entries is valid");
	*num_entries = (size_t) li.li_entries;
	templateInfo = malloc((size_t)li.li_entries * sizeof(struct ledger_template_info));
	T_QUIET; T_ASSERT_NOTNULL(templateInfo, "malloc entries");

	footprint_index = 0;
	ret = ledger(LEDGER_TEMPLATE_INFO, (caddr_t) templateInfo, (caddr_t) num_entries, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "ledger(LEDGER_TEMPLATE_INFO)");
	for (i = 0; i < *num_entries; i++) {
		if (strcmp(templateInfo[i].lti_name, "phys_footprint") == 0) {
			footprint_index = i;
			found = true;
		}
	}
	free(templateInfo);
	T_QUIET; T_ASSERT_TRUE(found, "found phys_footprint in ledger");
	return footprint_index;
}

static int64_t
get_ledger_entry_for_pid(pid_t pid, size_t index, size_t num_entries)
{
	int ret;
	int64_t value;
	struct ledger_entry_info *lei = NULL;

	lei = malloc(num_entries * sizeof(*lei));
	ret = ledger(LEDGER_ENTRY_INFO, (caddr_t) (uintptr_t) pid, (caddr_t) lei, (caddr_t) &num_entries);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "ledger(LEDGER_ENTRY_INFO)");
	value = lei[index].lei_balance;
	free(lei);
	return value;
}

static pid_t child_pid;

static void
test_after_background_helper_launches(char* variant, char * arg1, dispatch_block_t test_block, dispatch_block_t exit_block)
{
	char **launch_tool_args;
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size;

	dispatch_source_t ds_signal, ds_exit;

	/* Wait for the child process to tell us that it's ready, and then freeze it */
	signal(SIGUSR1, SIG_IGN);
	ds_signal = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_NOTNULL(ds_signal, "dispatch_source_create");
	dispatch_source_set_event_handler(ds_signal, test_block);

	dispatch_activate(ds_signal);

	testpath_buf_size = sizeof(testpath);
	int ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "_NSGetExecutablePath");
	T_LOG("Executable path: %s", testpath);
	launch_tool_args = (char *[]){
		testpath,
		"-n",
		variant,
		arg1,
		NULL
	};

	/* Spawn the child process. */
	ret = dt_launch_tool(&child_pid, launch_tool_args, false, NULL, NULL);
	if (ret != 0) {
		T_LOG("dt_launch tool returned %d with error code %d", ret, errno);
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(child_pid, "dt_launch_tool");

	/* Listen for exit. */
	ds_exit = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, (uintptr_t)child_pid, DISPATCH_PROC_EXIT, dispatch_get_main_queue());
	dispatch_source_set_event_handler(ds_exit, exit_block);

	dispatch_activate(ds_exit);
	dispatch_main();
}

T_DECL(vm_reclaim_full_reclaim_on_suspend, "Defer free memory and then suspend.",
    T_META_ASROOT(true),
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	test_after_background_helper_launches("allocate_and_suspend", "20", ^{
		int ret = 0;
		size_t num_ledger_entries = 0;
		size_t phys_footprint_index = ledger_phys_footprint_index(&num_ledger_entries);
		int64_t before_footprint, after_footprint, reclaimable_bytes = 20 * (1ULL << 20);
		before_footprint = get_ledger_entry_for_pid(child_pid, phys_footprint_index, num_ledger_entries);
		T_QUIET; T_EXPECT_GE(before_footprint, reclaimable_bytes, "memory was allocated");
		ret = pid_suspend(child_pid);
		T_ASSERT_POSIX_SUCCESS(ret, "child suspended");
		/*
		 * The reclaim work is kicked off asynchronously by the suspend.
		 * So we need to call into the kernel to synchronize with the reclaim worker
		 * thread.
		 */
		wait_for_pid_to_be_drained(child_pid);
		after_footprint = get_ledger_entry_for_pid(child_pid, phys_footprint_index, num_ledger_entries);
		T_QUIET; T_EXPECT_LE(after_footprint, before_footprint - reclaimable_bytes, "memory was reclaimed");

		resume_and_kill_proc(child_pid);
	},
	    ^{
		int status = 0, code = 0;
		pid_t rc = waitpid(child_pid, &status, 0);
		T_QUIET; T_ASSERT_EQ(rc, child_pid, "waitpid");
		code = WEXITSTATUS(status);
		T_QUIET; T_ASSERT_EQ(code, 0, "Child exited cleanly");
		T_END;
	});
}

T_DECL(vm_reclaim_limit_kills, "Deferred reclaims are processed before a limit kill",
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	int err;
	const size_t kNumEntries = 50;
	static const size_t kAllocationSize = (1UL << 20); // 1MB
	static const size_t kMemoryLimit = kNumEntries / 10 * kAllocationSize;

	mach_vm_reclaim_ring_t ringbuffer = ringbuffer_init();

	err = set_memlimits(getpid(), kMemoryLimit >> 20, kMemoryLimit >> 20, TRUE, TRUE);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "set_memlimits");

	for (size_t i = 0; i < kNumEntries; i++) {
		mach_vm_address_t addr = 0;
		mach_vm_reclaim_id_t idx = allocate_and_defer_deallocate(kAllocationSize, ringbuffer, (unsigned char) i, &addr);
		T_QUIET; T_ASSERT_EQ(idx, (mach_vm_reclaim_id_t)i, "idx is correct");
	}

	T_PASS("Was able to allocate and defer free %zu chunks of size %zu bytes while staying under limit of %zu bytes", kNumEntries, kAllocationSize, kMemoryLimit);
}

#if TARGET_OS_IOS && !TARGET_OS_VISION
T_DECL(vm_reclaim_update_reclaimable_bytes_threshold, "Kernel reclaims when num_bytes_reclaimable crosses threshold",
    T_META_SYSCTL_INT("vm.reclaim.max_threshold=16384"),
    T_META_TAG_VM_PREFERRED)
{
	mach_vm_reclaim_count_t kNumEntries = 0;
	const size_t kAllocationSize = vm_kernel_page_size;
	uint64_t vm_reclaim_reclaimable_max_threshold;
	int ret;
	mach_error_t err;
	size_t len = sizeof(vm_reclaim_reclaimable_max_threshold);
	size_t num_ledger_entries = 0;
	size_t phys_footprint_index = ledger_phys_footprint_index(&num_ledger_entries);

	mach_vm_reclaim_ring_t ringbuffer = ringbuffer_init();

	// Allocate 1000 times the reclaim threshold
	ret = sysctlbyname("vm.reclaim.max_threshold", &vm_reclaim_reclaimable_max_threshold, &len, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "vm.reclaim.max_threshold");
	kNumEntries = (mach_vm_reclaim_count_t)(vm_reclaim_reclaimable_max_threshold / kAllocationSize * 1000);
	mach_vm_reclaim_count_t capacity;
	err = mach_vm_reclaim_ring_capacity(ringbuffer, &capacity);
	T_QUIET; T_ASSERT_MACH_SUCCESS(err, "mach_vm_reclaim_ring_capacity()");
	T_QUIET; T_ASSERT_LT(kNumEntries, capacity, "Test does not fill up ringbuffer");

	mach_vm_address_t addr = 0;
	for (uint64_t i = 0; i < kNumEntries; i++) {
		mach_vm_reclaim_id_t idx = allocate_and_defer_deallocate(kAllocationSize, ringbuffer, (unsigned char)i, &addr);
		T_QUIET; T_ASSERT_EQ(idx, i, "idx is correct");
	}

	T_QUIET; T_ASSERT_LT(get_ledger_entry_for_pid(getpid(), phys_footprint_index, num_ledger_entries),
	    (int64_t) ((kNumEntries) * kAllocationSize), "Entries were reclaimed as we crossed threshold");
}
#else /* !TARGET_OS_IPHONE */
T_DECL(vm_reclaim_trim_minimum,
    "update_accounting trims buffer according to sampling minimum",
    T_META_VM_RECLAIM_ENABLED, T_META_TAG_VM_PREFERRED)
{
	kern_return_t kr;
	int ret;
	bool success, update_accounting;
	mach_vm_reclaim_ring_t ringbuffer;
	uint64_t sampling_period_ns;
	size_t sampling_period_size = sizeof(sampling_period_ns);
	uint32_t sizes[3] = {MiB(128), MiB(128), MiB(128)};
	mach_vm_address_t addrs[3] = {0};
	uint64_t ids[3] = {0};

	ret = sysctlbyname("vm.reclaim.sampling_period_ns", &sampling_period_ns, &sampling_period_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname(\"vm.reclaim.sampling_period_ns\")");
	struct timespec ts = {
		.tv_sec = 2 * sampling_period_ns / NSEC_PER_SEC,
		.tv_nsec = 2 * sampling_period_ns % NSEC_PER_SEC,
	};

	ringbuffer = ringbuffer_init();

	// This should result in a sample taken (min 0)
	kr = mach_vm_reclaim_update_kernel_accounting(ringbuffer);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_update_kernel_accounting()");

	for (int i = 0; i < 3; i++) {
		T_LOG("Placing entries[%d] into buffer", i);
		ids[i] = allocate_and_defer_deallocate(sizes[i], ringbuffer, 0xAB, &addrs[i]);
	}

	for (int i = 0; i < 3; i++) {
		// The minimum for the first sample should be 0
		success = try_cancel(ringbuffer, ids[i], addrs[i], sizes[i], VM_RECLAIM_DEALLOCATE);
		T_ASSERT_TRUE(success, "Entry %d should not be reclaimed", i);
		kr = mach_vm_reclaim_try_enter(ringbuffer, addrs[i], sizes[i], VM_RECLAIM_DEALLOCATE, &ids[i], &update_accounting);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_try_enter()");
		if (update_accounting) {
			kr = mach_vm_reclaim_update_kernel_accounting(ringbuffer);
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_update_kernel_accounting()");
		}
	}

	T_LOG("Sleeping for 2 sampling periods (%llu ns)", 2 * sampling_period_ns);
	ret = nanosleep(&ts, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "nanosleep()");

	// This should result in a sample taken (still min 0)
	kr = mach_vm_reclaim_update_kernel_accounting(ringbuffer);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_update_kernel_accounting()");

	for (int i = 0; i < 3; i++) {
		success = try_cancel(ringbuffer, ids[i], addrs[i], sizes[i], VM_RECLAIM_DEALLOCATE);
		T_EXPECT_TRUE(success, "Entry %d should not be reclaimed", i);
		kr = mach_vm_reclaim_try_enter(ringbuffer, addrs[i], sizes[i], VM_RECLAIM_DEALLOCATE, &ids[i], &update_accounting);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_try_enter()");
		if (update_accounting) {
			kr = mach_vm_reclaim_update_kernel_accounting(ringbuffer);
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_update_kernel_accounting()");
		}
	}
	T_LOG("Sleeping for 2 sampling periods (%llu ns)", 2 * sampling_period_ns);
	ret = nanosleep(&ts, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "nanosleep()");

	// This should result in a sample taken (still min 0)
	kr = mach_vm_reclaim_update_kernel_accounting(ringbuffer);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_update_kernel_accounting()");

	T_LOG("Sleeping for 2 sampling periods (%llu ns)", 2 * sampling_period_ns);
	ret = nanosleep(&ts, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "nanosleep()");

	// This should result in a sample taken (min sum(sizeof(entries[i])))
	kr = mach_vm_reclaim_update_kernel_accounting(ringbuffer);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_update_kernel_accounting()");

	for (int i = 0; i < 3; i++) {
		success = try_cancel(ringbuffer, ids[i], addrs[i], sizes[i], VM_RECLAIM_DEALLOCATE);
		T_EXPECT_FALSE(success, "Entry %d should not be reclaimed", i);
	}
}
#endif /* TARGET_OS_IPHONE */

T_HELPER_DECL(deallocate_buffer,
    "deallocate the buffer from underneath the kernel")
{
	kern_return_t kr;
	static const size_t kAllocationSize = (1UL << 20); // 1MB
	mach_vm_address_t addr;

	mach_vm_reclaim_ring_t ringbuffer = ringbuffer_init();

	mach_vm_reclaim_id_t idx = allocate_and_defer_deallocate(kAllocationSize, ringbuffer, 1, &addr);
	T_QUIET; T_ASSERT_EQ(idx, 0ULL, "Entry placed at start of buffer");
	mach_vm_reclaim_count_t capacity;
	kr = mach_vm_reclaim_ring_capacity(ringbuffer, &capacity);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ring_capacity()");

	mach_vm_size_t buffer_size = (size_t)capacity *
	    sizeof(struct mach_vm_reclaim_entry_s) + offsetof(struct mach_vm_reclaim_ring_s, entries);
	kr = mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)ringbuffer, buffer_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate");

	mach_vm_reclaim_ring_flush(ringbuffer, 10);

	T_FAIL("Test did not crash when synchronizing on a deallocated buffer!");
}

T_DECL(vm_reclaim_copyio_buffer_error, "Force a copyio error on the buffer",
    T_META_IGNORECRASHES(".*deallocate_buffer.*"),
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	int status = spawn_helper_and_wait_for_exit("deallocate_buffer");
	T_QUIET; T_ASSERT_TRUE(WIFSIGNALED(status), "Test process crashed.");
	T_QUIET; T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "Test process crashed with SIGKILL.");
}

T_HELPER_DECL(dealloc_gap, "Put a bad entry in the buffer")
{
	kern_return_t kr;
	static const size_t kAllocationSize = (1UL << 20); // 1MB
	mach_vm_address_t addr;
	bool should_update_kernel_accounting = false;

	kr = task_set_exc_guard_behavior(mach_task_self(), TASK_EXC_GUARD_ALL);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_set_exc_guard_behavior()");

	mach_vm_reclaim_ring_t ringbuffer = ringbuffer_init();

	mach_vm_reclaim_id_t idx = allocate_and_defer_deallocate(kAllocationSize, ringbuffer, 1, &addr);
	T_QUIET; T_ASSERT_EQ(idx, 0ULL, "Entry placed at start of buffer");
	idx = VM_RECLAIM_ID_NULL;
	kr = mach_vm_reclaim_try_enter(ringbuffer, addr, kAllocationSize, VM_RECLAIM_DEALLOCATE, &idx, &should_update_kernel_accounting);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_try_enter()");
	T_QUIET; T_ASSERT_EQ(idx, 1ULL, "Entry placed at correct index");

	mach_vm_reclaim_ring_flush(ringbuffer, 2);

	T_FAIL("Test did not crash when doing a double free!");
}

T_DECL(vm_reclaim_dealloc_gap, "Ensure a dealloc gap delivers a fatal exception",
    T_META_IGNORECRASHES(".*dealloc_gap.*"),
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	int status = spawn_helper_and_wait_for_exit("dealloc_gap");
	T_QUIET; T_ASSERT_TRUE(WIFSIGNALED(status), "Test process crashed.");
	T_QUIET; T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "Test process crashed with SIGKILL.");
}

T_HELPER_DECL(allocate_and_suspend_with_dealloc_gap,
    "defer double free, and signal parent to suspend")
{
	kern_return_t kr = task_set_exc_guard_behavior(mach_task_self(), TASK_EXC_GUARD_ALL);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_set_exc_guard_behavior()");
	allocate_and_suspend(argv, false, true);
}

static void
vm_reclaim_async_exception(char *variant, char *arg1)
{
	test_after_background_helper_launches(variant, arg1, ^{
		int ret = 0;
		ret = pid_suspend(child_pid);
		T_ASSERT_POSIX_SUCCESS(ret, "child suspended");
		/*
		 * The reclaim work is kicked off asynchronously by the suspend.
		 * So we need to call into the kernel to synchronize with the reclaim worker
		 * thread.
		 */
		T_LOG("Waiting for child to be drained...");
		wait_for_pid_to_be_drained(child_pid);
	}, ^{
		int status;
		int signal;
		T_LOG("Waiting for child to exit...");
		bool exited = dt_waitpid(child_pid, &status, &signal, 30);
		T_QUIET; T_EXPECT_FALSE(exited, "waitpid");
		T_QUIET; T_EXPECT_FALSE(status, "Test process crashed.");
		T_QUIET; T_EXPECT_EQ(signal, SIGKILL, "Test process crashed with SIGKILL.");
		T_END;
	});
}

T_DECL(vm_reclaim_dealloc_gap_async, "Ensure a dealloc gap delivers an async fatal exception",
    T_META_IGNORECRASHES(".*allocate_and_suspend_with_dealloc_gap.*"),
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	vm_reclaim_async_exception("allocate_and_suspend_with_dealloc_gap", "15");
}

T_HELPER_DECL(allocate_and_suspend_with_buffer_error,
    "defer free, free buffer, and signal parent to suspend")
{
	allocate_and_suspend(argv, true, false);
}

T_DECL(vm_reclaim_copyio_buffer_error_async, "Ensure a buffer copyio failure delivers an async fatal exception",
    T_META_IGNORECRASHES(".*allocate_and_suspend_with_buffer_error.*"),
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	vm_reclaim_async_exception("allocate_and_suspend_with_buffer_error", "15");
}

static mach_vm_reclaim_ring_t buffer_4fork_inherit;
static const size_t allocation_size_4fork_inherit = (16UL << 10); // 16 KiB
static const unsigned char value_4fork_inherit = 119;
static mach_vm_address_t addr_4fork_inherit;

T_HELPER_DECL(reuse_freed_entry_fork,
    "defer free, sync, and try to use entry")
{
	kern_return_t kr;
	bool usable, update;
	mach_vm_reclaim_id_t id = VM_RECLAIM_ID_NULL;
	mach_vm_reclaim_ring_t ringbuffer_tmp;
	kr = mach_vm_reclaim_ring_allocate(&ringbuffer_tmp, 1, 1);
	T_ASSERT_MACH_ERROR(kr, VM_RECLAIM_RESOURCE_SHORTAGE, "mach_vm_reclaim_ring_allocate() should fail");
	usable = try_cancel(buffer_4fork_inherit, 0, addr_4fork_inherit,
	    allocation_size_4fork_inherit, VM_RECLAIM_DEALLOCATE);
	T_ASSERT_TRUE(usable, "Entry can be re-used after fork()");

	T_EXPECT_EQ(*(unsigned char *)addr_4fork_inherit, value_4fork_inherit,
	    "value is preserved");

	kr = mach_vm_reclaim_try_enter(buffer_4fork_inherit,
	    addr_4fork_inherit, allocation_size_4fork_inherit, VM_RECLAIM_DEALLOCATE, &id, &update);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_try_enter()");
	T_EXPECT_EQ(id, 1ull, "new entry is placed at tail");

	kr = mach_vm_reclaim_ring_flush(buffer_4fork_inherit, 10);
	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ring_flush()");
}

T_DECL(inherit_buffer_after_fork, "Ensure reclaim buffer is inherited across a fork",
    T_META_IGNORECRASHES(".*vm_reclaim_fork.*"),
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	dt_helper_t helpers[1];

	buffer_4fork_inherit = ringbuffer_init();

	mach_vm_reclaim_id_t idx = allocate_and_defer_deallocate(
		allocation_size_4fork_inherit, buffer_4fork_inherit, value_4fork_inherit, &addr_4fork_inherit);
	T_QUIET; T_ASSERT_EQ(idx, 0ULL, "Entry placed at start of buffer");
	helpers[0] = dt_fork_helper("reuse_freed_entry_fork");
	dt_run_helpers(helpers, 1, 30);
}

#define SUSPEND_AND_RESUME_COUNT 4

// rdar://110081398
T_DECL(reclaim_async_on_repeated_suspend,
    "verify that subsequent suspends are allowed",
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	const int sleep_duration = 3;
	test_after_background_helper_launches("allocate_and_suspend", "20", ^{
		int ret = 0;
		for (int i = 0; i < SUSPEND_AND_RESUME_COUNT; i++) {
		        ret = pid_suspend(child_pid);
		        T_ASSERT_POSIX_SUCCESS(ret, "pid_suspend()");
		        ret = pid_resume(child_pid);
		        T_ASSERT_POSIX_SUCCESS(ret, "pid_resume()");
		}
		T_LOG("Sleeping %d sec...", sleep_duration);
		sleep(sleep_duration);
		T_LOG("Killing child...");
		T_QUIET; T_ASSERT_POSIX_SUCCESS(kill(child_pid, SIGKILL), "kill()");
	}, ^{
		int status;
		pid_t rc = waitpid(child_pid, &status, 0);
		T_QUIET; T_ASSERT_EQ(rc, child_pid, "waitpid");
		T_QUIET; T_ASSERT_EQ(WEXITSTATUS(status), 0, "Test process exited cleanly.");
		T_END;
	});
}

T_HELPER_DECL(buffer_init_after_exec,
    "initialize a ringbuffer after exec")
{
	mach_vm_reclaim_ring_t ringbuffer;
	kern_return_t kr = mach_vm_reclaim_ring_allocate(&ringbuffer, 1, 1);
	T_ASSERT_MACH_SUCCESS(kr, "post-exec: mach_vm_reclaim_ring_allocate()");
}

extern char **environ;

T_DECL(reclaim_exec_new_reclaim_buffer,
    "verify that an exec-ed process may instantiate a new buffer",
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	char **launch_tool_args;
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size;
	mach_vm_reclaim_ring_t ringbuffer;

	kern_return_t kr = mach_vm_reclaim_ring_allocate(&ringbuffer, 1, 1);
	T_ASSERT_MACH_SUCCESS(kr, "pre-exec: mach_vm_reclaim_ring_allocate()");

	testpath_buf_size = sizeof(testpath);
	int ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "_NSGetExecutablePath");
	T_LOG("Executable path: %s", testpath);
	launch_tool_args = (char *[]){
		testpath,
		"-n",
		"buffer_init_after_exec",
		NULL
	};

	/* Spawn the child process. */
	posix_spawnattr_t spawnattrs;
	posix_spawnattr_init(&spawnattrs);
	posix_spawnattr_setflags(&spawnattrs, POSIX_SPAWN_SETEXEC);
	posix_spawn(&child_pid, testpath, NULL, &spawnattrs, launch_tool_args, environ);
	T_ASSERT_FAIL("should not be reached");
}

T_DECL(resize_buffer,
    "verify that a reclaim buffer may be safely resized",
    T_META_VM_RECLAIM_ENABLED,
    T_META_TAG_VM_PREFERRED)
{
	kern_return_t kr;
	mach_vm_reclaim_ring_t ringbuffer;
	mach_vm_address_t addr_tmp;
	mach_vm_reclaim_id_t id_tmp;
	mach_vm_reclaim_id_t ids[4095] = {0};
	mach_vm_address_t addrs[4095] = {0};

	T_LOG("Initializing 1 page buffer");
	mach_vm_reclaim_count_t initial_len = mach_vm_reclaim_round_capacity(512);
	mach_vm_reclaim_count_t max_len = 4 * initial_len;
	kr = mach_vm_reclaim_ring_allocate(&ringbuffer, initial_len, max_len);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ring_allocate()");

	// Should be able to fit 1022 entries in a one-page buffer (two entries for indices)
	T_LOG("Filling buffer with entries");
	mach_vm_reclaim_count_t old_capacity;
	kr = mach_vm_reclaim_ring_capacity(ringbuffer, &old_capacity);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ring_capacity()");
	T_EXPECT_EQ(old_capacity, initial_len, "Capacity is same as asked for");
	for (mach_vm_reclaim_count_t i = 0; i < old_capacity; i++) {
		ids[i] = allocate_and_defer_deallocate(vm_page_size, ringbuffer, 'A', &addrs[i]);
		T_QUIET; T_ASSERT_NE(ids[i], VM_RECLAIM_ID_NULL, "Able to defer deallocation");
	}
	id_tmp = allocate_and_defer_deallocate(vm_page_size, ringbuffer, 'X', &addr_tmp);
	T_ASSERT_EQ(id_tmp, VM_RECLAIM_ID_NULL, "Unable to over-fill buffer");
	uint64_t initial_tail = os_atomic_load(&ringbuffer->indices.tail, relaxed);
	T_ASSERT_EQ(initial_tail, (uint64_t)old_capacity, "tail == capacity after fill");

	T_LOG("Resizing buffer to 4x");
	kr = mach_vm_reclaim_ring_resize(ringbuffer, max_len);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ring_resize()");

	// All entries should be reclaimed after resize
	T_EXPECT_EQ(os_atomic_load(&ringbuffer->indices.head, relaxed), initial_tail, "head is incremented");
	T_EXPECT_EQ(os_atomic_load(&ringbuffer->indices.busy, relaxed), initial_tail, "busy is incremented");
	T_EXPECT_EQ(os_atomic_load(&ringbuffer->indices.tail, relaxed), initial_tail, "tail is preserved");

	mach_vm_reclaim_count_t new_capacity;
	kr = mach_vm_reclaim_ring_capacity(ringbuffer, &new_capacity);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ring_capacity()");
	T_EXPECT_GT(new_capacity, old_capacity, "Buffer capacity grew");
	T_ASSERT_EQ(new_capacity, max_len, "length is set correctly");

	T_LOG("Attempting to use all entries (should fail)");
	for (mach_vm_reclaim_count_t i = 0; i < old_capacity; i++) {
		mach_vm_reclaim_state_t state;
		kr = mach_vm_reclaim_query_state(ringbuffer, ids[i], VM_RECLAIM_DEALLOCATE, &state);
		bool reclaimed = !(state == VM_RECLAIM_UNRECLAIMED);
		T_QUIET; T_EXPECT_TRUE(reclaimed, "Entry is reclaimed after resize");
		bool usable = try_cancel(ringbuffer, ids[i], addrs[i], vm_page_size, VM_RECLAIM_DEALLOCATE);
		T_QUIET; T_EXPECT_FALSE(usable, "Entry cannot be re-used after resize");
	}

	T_LOG("Filling resized buffer");
	for (mach_vm_reclaim_count_t i = 0; i < new_capacity; i++) {
		ids[i] = allocate_and_defer_deallocate(vm_page_size, ringbuffer, 'B', &addrs[i]);
		T_QUIET; T_ASSERT_NE(ids[i], VM_RECLAIM_ID_NULL, "Able to defer deallocation");
	}
	id_tmp = allocate_and_defer_deallocate(vm_page_size, ringbuffer, 'X', &addr_tmp);
	T_ASSERT_EQ(id_tmp, VM_RECLAIM_ID_NULL, "Unable to over-fill buffer");
	T_LOG("Re-using all entries");
	for (mach_vm_reclaim_count_t i = 0; i < new_capacity; i++) {
		bool usable = try_cancel(ringbuffer, ids[i], addrs[i], vm_page_size, VM_RECLAIM_DEALLOCATE);
		T_QUIET; T_EXPECT_TRUE(usable, "Entry is available for re-use");
	}
}
