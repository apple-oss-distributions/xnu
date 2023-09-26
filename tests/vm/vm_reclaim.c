#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_reclaim.h>
#include <mach-o/dyld.h>
#include <os/atomic_private.h>
#include <signal.h>
#include <unistd.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include <Kernel/kern/ledger.h>
extern int ledger(int cmd, caddr_t arg1, caddr_t arg2, caddr_t arg3);

#include "memorystatus_assertion_helpers.h"

// Some of the unit tests test deferred deallocations.
// For these we need to set a sufficiently large reclaim threshold
// to ensure their buffers aren't freed prematurely.
#define VM_RECLAIM_THRESHOLD_BOOTARG_HIGH "vm_reclaim_max_threshold=268435456"
#define VM_RECLAIM_THRESHOLD_BOOTARG_LOW "vm_reclaim_max_threshold=16384"
#define VM_RECLAIM_BOOTARG_DISABLED "vm_reclaim_max_threshold=0"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_ENABLED(TARGET_OS_IOS && !TARGET_OS_MACCATALYST),
	T_META_ENVVAR("MallocLargeCache=0") // Ensure we don't conflict with libmalloc's reclaim buffer
	);

T_DECL(vm_reclaim_init, "Set up and tear down a reclaim buffer",
    T_META_BOOTARGS_SET(VM_RECLAIM_THRESHOLD_BOOTARG_LOW))
{
	struct mach_vm_reclaim_ringbuffer_v1_s ringbuffer;

	kern_return_t kr = mach_vm_reclaim_ringbuffer_init(&ringbuffer);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ringbuffer_init");
}

T_DECL(vm_reclaim_init_fails_when_disabled, "Initializing a ring buffer on a system with vm_reclaim disabled should fail",
    T_META_BOOTARGS_SET(VM_RECLAIM_BOOTARG_DISABLED))
{
	struct mach_vm_reclaim_ringbuffer_v1_s ringbuffer;

	kern_return_t kr = mach_vm_reclaim_ringbuffer_init(&ringbuffer);

	T_QUIET; T_EXPECT_MACH_ERROR(kr, KERN_FAILURE, "mach_vm_reclaim_ringbuffer_init");
}

/*
 * Allocate a buffer of the given size, write val to each byte, and free it via a deferred free call.
 */
static uint64_t
allocate_and_defer_free(size_t size, mach_vm_reclaim_ringbuffer_v1_t ringbuffer, unsigned char val, mach_vm_address_t *addr /* OUT */)
{
	kern_return_t kr = mach_vm_map(mach_task_self(), addr, size, 0, VM_FLAGS_ANYWHERE, MEMORY_OBJECT_NULL, 0, FALSE, VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
	bool should_update_kernel_accounting = false;
	uint64_t idx;
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_map");

	memset((void *) *addr, val, size);

	idx = mach_vm_reclaim_mark_free(ringbuffer, *addr, (uint32_t) size, &should_update_kernel_accounting);
	if (should_update_kernel_accounting) {
		mach_vm_reclaim_update_kernel_accounting(ringbuffer);
	}
	return idx;
}

T_DECL(vm_reclaim_single_entry, "Place a single entry in the buffer and call sync",
    T_META_BOOTARGS_SET(VM_RECLAIM_THRESHOLD_BOOTARG_LOW))
{
	struct mach_vm_reclaim_ringbuffer_v1_s ringbuffer;
	static const size_t kAllocationSize = (1UL << 20); // 1MB
	mach_vm_address_t addr;

	kern_return_t kr = mach_vm_reclaim_ringbuffer_init(&ringbuffer);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ringbuffer_init");

	uint64_t idx = allocate_and_defer_free(kAllocationSize, &ringbuffer, 1, &addr);
	T_QUIET; T_ASSERT_EQ(idx, 0ULL, "Entry placed at start of buffer");
	mach_vm_reclaim_synchronize(&ringbuffer, 1);
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
 * Check that the given (freed) buffer has changed.
 * This will likely crash, but if we make it through the entire buffer then segfault on purpose.
 */
static void
assert_buffer_has_changed_and_crash(mach_vm_address_t addr, size_t size, unsigned char expected)
{
	/*
	 * mach_vm_reclaim_synchronize should have ensured the buffer was freed.
	 * Two cases:
	 * 1. The buffer is still still free (touching it causes a crash)
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

T_HELPER_DECL(reuse_freed_entry,
    "defer free, sync, and try to use entry")
{
	struct mach_vm_reclaim_ringbuffer_v1_s ringbuffer;
	static const size_t kAllocationSize = (1UL << 20); // 1MB
	mach_vm_address_t addr;
	static const unsigned char kValue = 220;

	kern_return_t kr = mach_vm_reclaim_ringbuffer_init(&ringbuffer);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ringbuffer_init");

	uint64_t idx = allocate_and_defer_free(kAllocationSize, &ringbuffer, kValue, &addr);
	T_QUIET; T_ASSERT_EQ(idx, 0ULL, "Entry placed at start of buffer");
	kr = mach_vm_reclaim_synchronize(&ringbuffer, 10);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_synchronize");
	assert_buffer_has_changed_and_crash(addr, kAllocationSize, kValue);
}

T_DECL(vm_reclaim_single_entry_verify_free, "Place a single entry in the buffer and call sync",
    T_META_IGNORECRASHES("vm_reclaim_single_entry_verify_free*"),
    T_META_BOOTARGS_SET(VM_RECLAIM_THRESHOLD_BOOTARG_LOW))
{
	int status = spawn_helper_and_wait_for_exit("reuse_freed_entry");
	T_QUIET; T_ASSERT_TRUE(WIFSIGNALED(status), "Test process crashed.");
	T_QUIET; T_ASSERT_EQ(WTERMSIG(status), SIGSEGV, "Test process crashed with segmentation fault.");
}

static void
allocate_and_suspend(char *const *argv, bool free_buffer, bool double_free)
{
	struct mach_vm_reclaim_ringbuffer_v1_s ringbuffer;
	static const size_t kAllocationSize = (1UL << 20); // 1MB
	mach_vm_address_t addr = 0;
	bool should_update_kernel_accounting = false;

	const mach_vm_size_t kNumEntries = (size_t) atoi(argv[0]);

	kern_return_t kr = mach_vm_reclaim_ringbuffer_init(&ringbuffer);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ringbuffer_init");
	T_QUIET; T_ASSERT_LT(kNumEntries, ringbuffer.buffer_len, "Test does not fill up ringubffer");

	for (size_t i = 0; i < kNumEntries; i++) {
		uint64_t idx = allocate_and_defer_free(kAllocationSize, &ringbuffer, (unsigned char) i, &addr);
		T_QUIET; T_ASSERT_EQ(idx, (uint64_t) i, "idx is correct");
	}

	if (double_free) {
		// Double free the last entry
		mach_vm_reclaim_mark_free(&ringbuffer, addr, (uint32_t) kAllocationSize, &should_update_kernel_accounting);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_mark_free");
	}

	if (free_buffer) {
		kr = mach_vm_deallocate(mach_task_self(), (mach_vm_address_t) ringbuffer.buffer, ringbuffer.buffer_len * sizeof(mach_vm_reclaim_entry_v1_t));
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate");
	}

	// Signal to our parent to suspend us
	if (kill(getppid(), SIGUSR1) != 0) {
		T_LOG("Unable to signal to parent process!");
		exit(1);
	}

	while (1) {
		;
	}
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
drain_async_queue(pid_t child_pid)
{
	int val = child_pid;
	int ret;
	size_t len = sizeof(val);
	ret = sysctlbyname("vm.reclaim_drain_async_queue", NULL, NULL, &val, len);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "vm.reclaim_drain_async_queue");
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
    T_META_BOOTARGS_SET(VM_RECLAIM_THRESHOLD_BOOTARG_HIGH))
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
		drain_async_queue(child_pid);

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
    T_META_BOOTARGS_SET(VM_RECLAIM_THRESHOLD_BOOTARG_LOW))
{
	int err;
	struct mach_vm_reclaim_ringbuffer_v1_s ringbuffer;
	const size_t kNumEntries = 50;
	static const size_t kAllocationSize = (1UL << 20); // 1MB
	static const size_t kMemoryLimit = kNumEntries / 10 * kAllocationSize;

	kern_return_t kr = mach_vm_reclaim_ringbuffer_init(&ringbuffer);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ringbuffer_init");

	err = set_memlimits(getpid(), kMemoryLimit >> 20, kMemoryLimit >> 20, TRUE, TRUE);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "set_memlimits");

	for (size_t i = 0; i < kNumEntries; i++) {
		mach_vm_address_t addr = 0;
		uint64_t idx = allocate_and_defer_free(kAllocationSize, &ringbuffer, (unsigned char) i, &addr);
		T_QUIET; T_ASSERT_EQ(idx, (uint64_t) i, "idx is correct");
	}

	T_PASS("Was able to allocate and defer free %zu chunks of size %zu bytes while staying under limit of %zu bytes", kNumEntries, kAllocationSize, kMemoryLimit);
}

T_DECL(vm_reclaim_update_reclaimable_bytes_threshold, "Kernel reclaims when num_bytes_reclaimable crosses threshold",
    T_META_BOOTARGS_SET(VM_RECLAIM_THRESHOLD_BOOTARG_LOW))
{
	mach_vm_size_t kNumEntries = 0;
	struct mach_vm_reclaim_ringbuffer_v1_s ringbuffer;
	const size_t kAllocationSize = vm_kernel_page_size;
	uint64_t vm_reclaim_reclaimable_max_threshold;
	int ret;
	size_t len = sizeof(vm_reclaim_reclaimable_max_threshold);
	size_t num_ledger_entries = 0;
	size_t phys_footprint_index = ledger_phys_footprint_index(&num_ledger_entries);

	kern_return_t kr = mach_vm_reclaim_ringbuffer_init(&ringbuffer);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ringbuffer_init");

	// Allocate 1000 times the reclaim threshold
	ret = sysctlbyname("vm.reclaim_max_threshold", &vm_reclaim_reclaimable_max_threshold, &len, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "vm.reclaim_max_threshold");
	kNumEntries = vm_reclaim_reclaimable_max_threshold / kAllocationSize * 1000;
	T_QUIET; T_ASSERT_LT(kNumEntries, ringbuffer.buffer_len, "Entries will not fill up ringbuffer.");

	mach_vm_address_t addr = 0;
	for (uint64_t i = 0; i < kNumEntries; i++) {
		uint64_t idx = allocate_and_defer_free(kAllocationSize, &ringbuffer, (unsigned char) i, &addr);
		T_QUIET; T_ASSERT_EQ(idx, i, "idx is correct");
	}

	T_QUIET; T_ASSERT_LT(get_ledger_entry_for_pid(getpid(), phys_footprint_index, num_ledger_entries),
	    (int64_t) ((kNumEntries) * kAllocationSize), "Entries were reclaimed as we crossed threshold");
}

T_HELPER_DECL(deallocate_indices,
    "deallocate the indices from underneath the kernel")
{
	mach_vm_reclaim_ringbuffer_v1_t ringbuffer = NULL;
	static const size_t kAllocationSize = (1UL << 20); // 1MB
	mach_vm_address_t addr;

	kern_return_t kr;
	kr = mach_vm_map(mach_task_self(), (mach_vm_address_t *) &ringbuffer, vm_page_size, 0, VM_FLAGS_ANYWHERE, MEMORY_OBJECT_NULL, 0, FALSE, VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_map");
	kr = mach_vm_reclaim_ringbuffer_init(ringbuffer);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ringbuffer_init");

	uint64_t idx = allocate_and_defer_free(kAllocationSize, ringbuffer, 1, &addr);
	T_QUIET; T_ASSERT_EQ(idx, 0ULL, "Entry placed at start of buffer");
	kr = mach_vm_deallocate(mach_task_self(), (mach_vm_address_t) ringbuffer, vm_page_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate");

	mach_vm_reclaim_synchronize(ringbuffer, 10);

	T_FAIL("Test did not crash when synchronizing with deallocated indices");
}

T_DECL(vm_reclaim_copyio_indices_error, "Force a copyio error on the indices",
    T_META_IGNORECRASHES("vm_reclaim_copyio_indices_error*"),
    T_META_BOOTARGS_SET(VM_RECLAIM_THRESHOLD_BOOTARG_LOW))
{
	int status = spawn_helper_and_wait_for_exit("deallocate_indices");
	T_QUIET; T_ASSERT_TRUE(WIFSIGNALED(status), "Test process crashed.");
	T_QUIET; T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "Test process crashed with SIGKILL.");
}

T_HELPER_DECL(deallocate_buffer,
    "deallocate the buffer from underneath the kernel")
{
	struct mach_vm_reclaim_ringbuffer_v1_s ringbuffer;
	static const size_t kAllocationSize = (1UL << 20); // 1MB
	mach_vm_address_t addr;

	kern_return_t kr = mach_vm_reclaim_ringbuffer_init(&ringbuffer);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ringbuffer_init");

	uint64_t idx = allocate_and_defer_free(kAllocationSize, &ringbuffer, 1, &addr);
	T_QUIET; T_ASSERT_EQ(idx, 0ULL, "Entry placed at start of buffer");
	kr = mach_vm_deallocate(mach_task_self(), (mach_vm_address_t) ringbuffer.buffer, ringbuffer.buffer_len * sizeof(mach_vm_reclaim_entry_v1_t));
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate");

	mach_vm_reclaim_synchronize(&ringbuffer, 10);

	T_FAIL("Test did not crash when synchronizing on a deallocated buffer!");
}

T_DECL(vm_reclaim_copyio_buffer_error, "Force a copyio error on the buffer",
    T_META_IGNORECRASHES("vm_reclaim_copyio_buffer_error*"),
    T_META_BOOTARGS_SET(VM_RECLAIM_THRESHOLD_BOOTARG_HIGH))
{
	int status = spawn_helper_and_wait_for_exit("deallocate_buffer");
	T_QUIET; T_ASSERT_TRUE(WIFSIGNALED(status), "Test process crashed.");
	T_QUIET; T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "Test process crashed with SIGKILL.");
}

T_HELPER_DECL(dealloc_gap, "Put a bad entry in the buffer")
{
	struct mach_vm_reclaim_ringbuffer_v1_s ringbuffer;
	static const size_t kAllocationSize = (1UL << 20); // 1MB
	mach_vm_address_t addr;
	bool should_update_kernel_accounting = false;

	kern_return_t kr = mach_vm_reclaim_ringbuffer_init(&ringbuffer);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ringbuffer_init");

	uint64_t idx = allocate_and_defer_free(kAllocationSize, &ringbuffer, 1, &addr);
	T_QUIET; T_ASSERT_EQ(idx, 0ULL, "Entry placed at start of buffer");
	idx = mach_vm_reclaim_mark_free(&ringbuffer, addr, (uint32_t) kAllocationSize, &should_update_kernel_accounting);
	T_QUIET; T_ASSERT_EQ(idx, 1ULL, "Entry placed at correct index");

	mach_vm_reclaim_synchronize(&ringbuffer, 2);

	T_FAIL("Test did not crash when doing a double free!");
}

T_DECL(vm_reclaim_dealloc_gap, "Ensure a dealloc gap delivers a fatal exception",
    T_META_IGNORECRASHES("vm_reclaim_dealloc_gap*"),
    T_META_BOOTARGS_SET(VM_RECLAIM_THRESHOLD_BOOTARG_LOW))
{
	int status = spawn_helper_and_wait_for_exit("dealloc_gap");
	T_QUIET; T_ASSERT_TRUE(WIFSIGNALED(status), "Test process crashed.");
	T_QUIET; T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "Test process crashed with SIGKILL.");
}

T_HELPER_DECL(allocate_and_suspend_with_dealloc_gap,
    "defer double free, and signal parent to suspend")
{
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
		drain_async_queue(child_pid);
	}, ^{
		int status;
		pid_t rc = waitpid(child_pid, &status, 0);
		T_QUIET; T_ASSERT_EQ(rc, child_pid, "waitpid");
		T_QUIET; T_ASSERT_TRUE(WIFSIGNALED(status), "Test process crashed.");
		T_QUIET; T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "Test process crashed with SIGKILL.");
		T_END;
	});
}

T_DECL(vm_reclaim_dealloc_gap_async, "Ensure a dealloc gap delivers an async fatal exception",
    T_META_IGNORECRASHES("vm_reclaim_dealloc_gap_async*"),
    T_META_BOOTARGS_SET(VM_RECLAIM_THRESHOLD_BOOTARG_LOW))
{
	vm_reclaim_async_exception("allocate_and_suspend_with_dealloc_gap", "15");
}

T_HELPER_DECL(allocate_and_suspend_with_buffer_error,
    "defer free, free buffer, and signal parent to suspend")
{
	allocate_and_suspend(argv, true, false);
}

T_DECL(vm_reclaim_copyio_buffer_error_async, "Ensure a buffer copyio failure delivers an async fatal exception",
    T_META_IGNORECRASHES("vm_reclaim_dealloc_gap_async*"),
    T_META_BOOTARGS_SET(VM_RECLAIM_THRESHOLD_BOOTARG_HIGH))
{
	vm_reclaim_async_exception("allocate_and_suspend_with_buffer_error", "15");
}

T_HELPER_DECL(reuse_freed_entry_fork,
    "defer free, sync, and try to use entry")
{
	struct mach_vm_reclaim_ringbuffer_v1_s ringbuffer;
	static const size_t kAllocationSize = (1UL << 20); // 1MB
	mach_vm_address_t addr;
	static const unsigned char kValue = 119;

	kern_return_t kr = mach_vm_reclaim_ringbuffer_init(&ringbuffer);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_ringbuffer_init");

	uint64_t idx = allocate_and_defer_free(kAllocationSize, &ringbuffer, kValue, &addr);
	T_QUIET; T_ASSERT_EQ(idx, 0ULL, "Entry placed at start of buffer");

	pid_t forked_pid = fork();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NE(forked_pid, -1, "fork()");
	if (forked_pid == 0) {
		kr = mach_vm_reclaim_synchronize(&ringbuffer, 10);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_reclaim_synchronize");
		assert_buffer_has_changed_and_crash(addr, kAllocationSize, kValue);
	} else {
		int status;
		pid_t rc = waitpid(forked_pid, &status, 0);
		T_QUIET; T_ASSERT_EQ(rc, forked_pid, "waitpid");
		T_QUIET; T_ASSERT_TRUE(WIFSIGNALED(status), "Forked process crashed.");
		T_QUIET; T_ASSERT_EQ(WTERMSIG(status), SIGSEGV, "Forked process crashed with segmentation fault.");
	}
}

T_DECL(vm_reclaim_fork, "Ensure reclaim buffer is inherited across a fork",
    T_META_IGNORECRASHES("vm_reclaim_fork*"),
    T_META_BOOTARGS_SET(VM_RECLAIM_THRESHOLD_BOOTARG_HIGH))
{
	int status = spawn_helper_and_wait_for_exit("reuse_freed_entry_fork");
	T_QUIET; T_ASSERT_TRUE(WIFEXITED(status), "Test process exited.");
	T_QUIET; T_ASSERT_EQ(WEXITSTATUS(status), 0, "Test process exited cleanly.");
}

#define SUSPEND_AND_RESUME_COUNT 4

// rdar://110081398
T_DECL(reclaim_async_on_repeated_suspend,
    "verify that subsequent suspends are allowed",
    T_META_BOOTARGS_SET(VM_RECLAIM_THRESHOLD_BOOTARG_HIGH))
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
