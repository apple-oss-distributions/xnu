#include <darwintest.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>
#include <TargetConditionals.h>
#include "excserver.h"
#include "exc_helpers.h"

extern int pid_hibernate(int pid);

static vm_address_t page_size;

T_GLOBAL_META(
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("peter_newman"),
	T_META_REQUIRES_SYSCTL_EQ("hw.optional.wkdm_popcount", 1)
	);

static vm_address_t *blocks;
static uint64_t block_count;
static const uint64_t block_length = 0x800000;

static uint32_t vm_pagesize;

static void
dirty_page(const vm_address_t address)
{
	assert((address & (page_size - 1)) == 0UL);
	uint32_t *const page_as_u32 = (uint32_t *)address;
	for (uint32_t i = 0; i < page_size / sizeof(uint32_t); i += 2) {
		page_as_u32[i + 0] = i % 4;
		page_as_u32[i + 1] = 0xcdcdcdcd;
	}
}

static bool
try_to_corrupt_page(vm_address_t page_va)
{
	int val;
	size_t size = sizeof(val);
	int result = sysctlbyname("vm.compressor_inject_error", &val, &size,
	    &page_va, sizeof(page_va));
	return result == 0;
}

static void
create_corrupted_regions(void)
{
	uint64_t hw_memsize;

	size_t size = sizeof(unsigned int);
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.pagesize", &vm_pagesize, &size,
	    NULL, 0), "read vm.pagesize");
	size = sizeof(uint64_t);
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("hw.memsize", &hw_memsize, &size,
	    NULL, 0), "read hw.memsize");

#if TARGET_OS_OSX
	const uint64_t max_memsize = 32ULL * 0x40000000ULL; // 32 GB
#else
	const uint64_t max_memsize = 8ULL * 0x100000ULL; // 8 MB
#endif
	const uint64_t effective_memsize = (hw_memsize > max_memsize) ?
	    max_memsize : hw_memsize;

	const uint64_t total_pages = effective_memsize / vm_pagesize;
	const uint64_t pages_per_block = block_length / vm_pagesize;

	// Map a as much memory as we have physical memory to back. Dirtying all
	// of these pages will force a compressor sweep. The mapping is done using
	// the smallest number of malloc() calls to allocate the necessary VAs.
	block_count = total_pages / pages_per_block;

	blocks = (vm_address_t *)malloc(sizeof(*blocks) * block_count);
	for (uint64_t i = 0; i < block_count; i++) {
		void *bufferp = malloc(block_length);
		blocks[i] = (vm_address_t)bufferp;
	}

	for (uint32_t i = 0; i < block_count; i++) {
		for (size_t buffer_offset = 0; buffer_offset < block_length;
		    buffer_offset += vm_pagesize) {
			dirty_page(blocks[i] + buffer_offset);
		}
	}

#if !TARGET_OS_OSX
	// We can't use a substantial amount of memory on embedded platforms, so
	// freeze the current process instead to cause everything to be compressed.
	T_ASSERT_POSIX_SUCCESS(pid_hibernate(-2), NULL);
	T_ASSERT_POSIX_SUCCESS(pid_hibernate(-2), NULL);
#endif

	uint32_t corrupt = 0;
	for (uint32_t i = 0; i < block_count; i++) {
		for (size_t buffer_offset = 0; buffer_offset < block_length;
		    buffer_offset += vm_pagesize) {
			if (try_to_corrupt_page(blocks[i] + buffer_offset)) {
				corrupt++;
			}
		}
	}

	T_LOG("corrupted %u/%llu pages. accessing...\n", corrupt, total_pages);
	if (corrupt == 0) {
		T_SKIP("no pages corrupted");
	}
}

static bool
try_write(volatile uint32_t *word __unused)
{
#ifdef __arm64__
	uint64_t val = 1;
	__asm__ volatile (
             "str		%w0, %1\n"
             "mov		%0, 0\n"
             : "+r"(val) : "m"(*word));
	// The exception handler skips over the instruction that zeroes val when a
	// decompression failure is detected.
	return val == 0;
#else
	return false;
#endif
}

static bool
read_blocks(void)
{
	for (uint32_t i = 0; i < block_count; i++) {
		for (size_t buffer_offset = 0; buffer_offset < block_length;
		    buffer_offset += vm_pagesize) {
			// Access pages until the fault is detected.
			if (!try_write((volatile uint32_t *)(blocks[i] + buffer_offset))) {
				T_LOG("test_thread breaking");
				return true;
			}
		}
	}
	return false;
}

static size_t
kern_memory_failure_handler(
	__unused mach_port_t task,
	__unused mach_port_t thread,
	exception_type_t exception,
	mach_exception_data_t code)
{
	T_EXPECT_EQ(exception, EXC_BAD_ACCESS,
	    "Verified bad address exception");
	T_EXPECT_EQ((int)code[0], KERN_MEMORY_FAILURE, "caught KERN_MEMORY_FAILURE");
	T_PASS("received KERN_MEMORY_FAILURE from test thread");
	// Skip the next instruction as well so that the faulting code can detect
	// the exception.
	return 8;
}

T_DECL(decompression_failure,
    "Confirm that exception is raised on decompression failure",
    // Disable software checks in development builds, as these would result in
    // panics.
    T_META_BOOTARGS_SET("vm_compressor_validation=0"),
    T_META_ASROOT(true),
    // This test intentionally corrupts pages backing heap memory, so it's
    // not practical for it to release all the buffers properly.
    T_META_CHECK_LEAKS(false))
{
	T_SETUPBEGIN;

#if !TARGET_OS_OSX
	if (pid_hibernate(-2) != 0) {
		T_SKIP("compressor not active");
	}
#endif

	int value;
	size_t size = sizeof(value);
	if (sysctlbyname("vm.compressor_inject_error", &value, &size, NULL, 0)
	    != 0) {
		T_SKIP("vm.compressor_inject_error not present");
	}

	T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.pagesize", &value, &size, NULL, 0),
	    NULL);
	T_ASSERT_EQ_ULONG(size, sizeof(value), NULL);
	page_size = (vm_address_t)value;

	mach_port_t exc_port = create_exception_port(EXC_MASK_BAD_ACCESS);
	create_corrupted_regions();
	T_SETUPEND;

	run_exception_handler(exc_port, kern_memory_failure_handler);

	if (!read_blocks()) {
		T_SKIP("no faults");
	}
}
