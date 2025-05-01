#include <darwintest.h>
#include <darwintest_utils.h>
#include <test_utils.h>

#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/memory_entry.h>
#include <mach/shared_region.h>
#include <mach/vm_reclaim.h>
#include <mach/vm_types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <TargetConditionals.h>
#include <mach-o/dyld.h>
#include <libgen.h>

#include <os/bsd.h> // For os_parse_boot_arg_int

// workarounds for buggy MIG declarations
// see tests/vm/vm_parameter_validation_replacement_*.defs
// and tests/Makefile for details
#include "vm_parameter_validation_replacement_mach_host.h"
#include "vm_parameter_validation_replacement_host_priv.h"

// code shared with kernel/kext tests
#include "../../osfmk/tests/vm_parameter_validation.h"

#define GOLDEN_FILES_VERSION "vm_parameter_validation_golden_images_edeef315.tar.xz"
#define GOLDEN_FILES_ASSET_FILE_POINTER GOLDEN_FILES_VERSION

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_S3_ASSET(GOLDEN_FILES_ASSET_FILE_POINTER),
	T_META_ASROOT(true),  /* required for vm_wire tests on macOS */
	T_META_RUN_CONCURRENTLY(false), /* vm_parameter_validation_kern uses kernel globals */
	T_META_ALL_VALID_ARCHS(true),
	XNU_T_META_REQUIRES_DEVELOPMENT_KERNEL
	);

/*
 * vm_parameter_validation.c
 * Test parameter validation of vm's userspace API
 *
 * The test compares the return values against a 'golden' list, which is a text
 * file previously generated and compressed in .xz files, per platform.
 * When vm_parameter_validation runs, it calls assets/vm_parameter_validation/decompress.sh,
 * which detects the platform and decompresses the corresponding user and kern
 * golden files.
 *
 * Any return code mismatch is reported as a failure, printing test name and iteration.
 * New tests not present in the 'golden' list will run but they are also reported as a failure.
 *
 * There are two environment variable flags that makes development work easier and
 * can temporarily disable golden list testing.
 *
 * SKIP_TESTS
 * When running with SKIP_TESTS set, the test will not compare the results
 * against the golden files.
 *
 * DUMP_RESULTS
 * When running with DUMP_RESULTS set, the test will print all the returned values
 * (as opposed to only the failing ones). To pretty-print this output use the python script:
 * DUMP_RESULTS=1 vm_parameter_validation | tools/format_vm_parameter_validation.py
 */



/*
 * xnu/libsyscall/mach/mach_vm.c intercepts some VM calls from userspace,
 * sometimes doing something other than the expected MIG call.
 * This test generates its own MIG userspace call sites to call the kernel
 * entrypoints directly, bypassing libsyscall's interference.
 *
 * The custom MIG call sites are generated into:
 * vm_parameter_validation_vm_map_user.c
 * vm_parameter_validation_mach_vm_user.c
 */

#pragma clang diagnostic ignored "-Wdeclaration-after-statement"
#pragma clang diagnostic ignored "-Wmissing-prototypes"
#pragma clang diagnostic ignored "-Wpedantic"

/*
 * Our wire tests often try to wire the whole address space.
 * In that case the error code is determined by the first range of addresses
 * that cannot be wired.
 * In most cases that is a protection failure on a malloc guard page. But
 * sometimes, circumstances outside of our control change the address map of
 * our test process and add holes, which means we get a bad address error
 * instead, and the test fails because the return code doesn't match what's
 * recorded in the golden files.
 * To avoid this, we want to keep a guard page inside our data section.
 * Because that data section is one of the first things in our address space,
 * the behavior of wire is (more) predictable.
 */
static _Alignas(KB16) char guard_page[KB16];

static void
set_up_guard_page(void)
{
	/*
	 * Ensure that _Alignas worked as expected.
	 */
	assert(0 == (((mach_vm_address_t)guard_page) & PAGE_MASK));
	/*
	 * Remove all permissions on guard_page such that it is a guard page.
	 */
	assert(0 == mprotect(guard_page, sizeof(guard_page), 0));
}

// Return a file descriptor that tests can read and write.
// A single temporary file is shared among all tests.
static int
get_fd()
{
	static int fd = -1;
	if (fd > 0) {
		return fd;
	}

	char filename[] = "/tmp/vm_parameter_validation_XXXXXX";
	fd = mkstemp(filename);
	assert(fd > 2);  // not stdin/stdout/stderr
	return fd;
}

static int rosetta_dyld_fd = -1;
// Return a file descriptor that Rosetta dyld will accept
static int
get_dyld_fd()
{
	if (rosetta_dyld_fd >= 0) {
		return rosetta_dyld_fd;
	}

	if (!isRosetta()) {
		rosetta_dyld_fd = 0;
		return rosetta_dyld_fd;
	}

	rosetta_dyld_fd = 0;
	return rosetta_dyld_fd;
}

// Close the Rosetta dyld fd (only one test calls this)
static void
close_dyld_fd()
{
	if (isRosetta()) {
		assert(rosetta_dyld_fd > 2);
		if (close(rosetta_dyld_fd) != 0) {
			assert(0);
		}
		rosetta_dyld_fd = -1;
	}
}

static int
munmap_helper(void *ptr, size_t size)
{
	mach_vm_address_t start, end;
	if (0 != size) { // munmap rejects size == 0 even though mmap accepts it
		/*
		 * munmap expects aligned inputs, even though mmap sometimes
		 * returns unaligned values
		 */
		start = ((mach_vm_address_t)ptr) & ~PAGE_MASK;
		end = (((mach_vm_address_t)ptr) + size + PAGE_MASK) & ~PAGE_MASK;
		return munmap((void*)start, end - start);
	}
	return 0;
}

// Some tests provoke EXC_GUARD exceptions.
// We disable EXC_GUARD if possible. If we can't, we disable those tests instead.
static bool EXC_GUARD_ENABLED = true;

static int
call_munlock(void *start, size_t size)
{
	int err = munlock(start, size);
	return err ? errno : 0;
}

static int
call_mlock(void *start, size_t size)
{
	int err = mlock(start, size);
	return err ? errno : 0;
}

extern int __munmap(void *, size_t);

static kern_return_t
call_munmap(MAP_T map __unused, mach_vm_address_t start, mach_vm_size_t size)
{
	int err = __munmap((void*)start, (size_t)size);
	return err ? errno : 0;
}

static int
call_mremap_encrypted(void *start, size_t size)
{
	int err = mremap_encrypted(start, size, CRYPTID_NO_ENCRYPTION, /*cputype=*/ 0, /*cpusubtype=*/ 0);
	return err ? errno : 0;
}

/////////////////////////////////////////////////////
// Mach tests

static mach_port_t
make_a_mem_object(mach_vm_size_t size)
{
	mach_port_t out_handle;
	kern_return_t kr = mach_memory_object_memory_entry_64(mach_host_self(), 1, size, VM_PROT_READ | VM_PROT_WRITE, 0, &out_handle);
	assert(kr == 0);
	return out_handle;
}

static mach_port_t
make_a_mem_entry(vm_size_t size)
{
	mach_port_t port;
	memory_object_size_t s = (memory_object_size_t)size;
	kern_return_t kr = mach_make_memory_entry_64(mach_host_self(), &s, (memory_object_offset_t)0, MAP_MEM_NAMED_CREATE | MAP_MEM_LEDGER_TAGGED, &port, MACH_PORT_NULL);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocate memory entry");
	return port;
}

static inline void
check_mach_memory_entry_outparam_changes(kern_return_t * kr, mach_port_t out_handle, mach_port_t saved_handle)
{
	if (*kr != KERN_SUCCESS) {
		if (out_handle != (mach_port_t) saved_handle) {
			*kr = OUT_PARAM_BAD;
		}
	}
}
// mach_make_memory_entry is really several functions wearing a trenchcoat.
// Run a separate test for each variation.

// mach_make_memory_entry also has a confusing number of entrypoints:
// U64: mach_make_memory_entry_64(64) (mach_make_memory_entry is the same MIG message)
// U32: mach_make_memory_entry(32), mach_make_memory_entry_64(64), _mach_make_memory_entry(64) (each is a unique MIG message)
#define IMPL(FN, T)                                                               \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__memonly(MAP_T map, T start, T size)                      \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_value = UNLIKELY_INITIAL_MACH_PORT;            \
	        mach_port_t out_handle = invalid_value;                           \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_ONLY, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                (void)mach_port_deallocate(mach_task_self(), out_handle); \
	/* MAP_MEM_ONLY doesn't use the size. It should not change it. */         \
	                if(io_size != size) {                                     \
	                        kr = OUT_PARAM_BAD;                               \
	                }                                                         \
	        }                                                                 \
	        (void)mach_port_deallocate(mach_task_self(), memobject);          \
	        check_mach_memory_entry_outparam_changes(&kr, out_handle, invalid_value); \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__namedcreate(MAP_T map, T start, T size)                  \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_value = UNLIKELY_INITIAL_MACH_PORT;            \
	        mach_port_t out_handle = invalid_value;                           \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_NAMED_CREATE, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                (void)mach_port_deallocate(mach_task_self(), out_handle); \
	        }                                                                 \
	        (void)mach_port_deallocate(mach_task_self(), memobject);          \
	        check_mach_memory_entry_outparam_changes(&kr, out_handle, invalid_value); \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__copy(MAP_T map, T start, T size)                         \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_value = UNLIKELY_INITIAL_MACH_PORT;            \
	        mach_port_t out_handle = invalid_value;                           \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_VM_COPY, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                (void)mach_port_deallocate(mach_task_self(), out_handle); \
	        }                                                                 \
	        (void)mach_port_deallocate(mach_task_self(), memobject);          \
	        check_mach_memory_entry_outparam_changes(&kr, out_handle, invalid_value); \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__share(MAP_T map, T start, T size)                         \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_value = UNLIKELY_INITIAL_MACH_PORT;            \
	        mach_port_t out_handle = invalid_value;                           \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_VM_SHARE, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                (void)mach_port_deallocate(mach_task_self(), out_handle); \
	        }                                                                 \
	        (void)mach_port_deallocate(mach_task_self(), memobject);          \
	        check_mach_memory_entry_outparam_changes(&kr, out_handle, invalid_value); \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__namedreuse(MAP_T map, T start, T size)                   \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_value = UNLIKELY_INITIAL_MACH_PORT;            \
	        mach_port_t out_handle = invalid_value;                           \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_NAMED_REUSE, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                (void)mach_port_deallocate(mach_task_self(), out_handle); \
	        }                                                                 \
	        (void)mach_port_deallocate(mach_task_self(), memobject);          \
	        check_mach_memory_entry_outparam_changes(&kr, out_handle, invalid_value); \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __vm_prot(MAP_T map, T start, T size, vm_prot_t prot)      \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_value = UNLIKELY_INITIAL_MACH_PORT;            \
	        mach_port_t out_handle = invalid_value;                           \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              prot, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                (void)mach_port_deallocate(mach_task_self(), out_handle); \
	        }                                                                 \
	        (void)mach_port_deallocate(mach_task_self(), memobject);          \
	        check_mach_memory_entry_outparam_changes(&kr, out_handle, invalid_value); \
	        return kr;                                                        \
	}

IMPL(mach_make_memory_entry_64, mach_vm_address_t)
#if TEST_OLD_STYLE_MACH
IMPL(mach_make_memory_entry, vm_address_t)
IMPL(_mach_make_memory_entry, mach_vm_address_t)
#endif
#undef IMPL

static inline void
check_mach_memory_object_memory_entry_outparam_changes(kern_return_t * kr, mach_port_t out_handle,
    mach_port_t saved_out_handle)
{
	if (*kr != KERN_SUCCESS) {
		if (out_handle != saved_out_handle) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

#define IMPL(FN) \
	static kern_return_t                                            \
	call_ ## FN ## __size(MAP_T map __unused, mach_vm_size_t size)  \
	{                                                               \
	        kern_return_t kr;                                       \
	        mach_port_t invalid_value = UNLIKELY_INITIAL_MACH_PORT;  \
	        mach_port_t out_entry = invalid_value;                  \
	        kr = FN(mach_host_self(), 1, size, VM_PROT_READ | VM_PROT_WRITE, 0, &out_entry); \
	        if (kr == 0) {                                          \
	                (void)mach_port_deallocate(mach_task_self(), out_entry); \
	        }                                                       \
	        check_mach_memory_object_memory_entry_outparam_changes(&kr, out_entry, invalid_value); \
	        return kr;                                              \
	}                                                               \
	static kern_return_t                                            \
	call_ ## FN ## __vm_prot(MAP_T map __unused, mach_vm_size_t size, vm_prot_t prot) \
	{                                                               \
	        kern_return_t kr;                                       \
	        mach_port_t invalid_value = UNLIKELY_INITIAL_MACH_PORT;  \
	        mach_port_t out_entry = invalid_value;                  \
	        kr = FN(mach_host_self(), 1, size, prot, 0, &out_entry); \
	        if (kr == 0) {                                          \
	                (void)mach_port_deallocate(mach_task_self(), out_entry); \
	        }                                                       \
	        check_mach_memory_object_memory_entry_outparam_changes(&kr, out_entry, invalid_value); \
	        return kr;                                              \
	}

// The declaration of mach_memory_object_memory_entry is buggy on U32.
// We compile in our own MIG user stub for it with a "replacement_" prefix.
// rdar://117927965
IMPL(replacement_mach_memory_object_memory_entry)
IMPL(mach_memory_object_memory_entry_64)
#undef IMPL

static inline void
check_vm_read_outparam_changes(kern_return_t * kr, mach_vm_size_t size, mach_vm_size_t requested_size,
    mach_vm_address_t addr)
{
	if (*kr == KERN_SUCCESS) {
		if (size != requested_size) {
			*kr = OUT_PARAM_BAD;
		}
		if (size == 0) {
			if (addr != 0) {
				*kr = OUT_PARAM_BAD;
			}
		}
	}
}


static kern_return_t
call_mach_vm_read(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	vm_offset_t out_addr = UNLIKELY_INITIAL_ADDRESS;
	mach_msg_type_number_t out_size = UNLIKELY_INITIAL_SIZE;
	kern_return_t kr = mach_vm_read(map, start, size, &out_addr, &out_size);
	if (kr == 0) {
		(void)mach_vm_deallocate(mach_task_self(), out_addr, out_size);
	}
	check_vm_read_outparam_changes(&kr, out_size, size, out_addr);
	return kr;
}
#if TEST_OLD_STYLE_MACH
static kern_return_t
call_vm_read(MAP_T map, vm_address_t start, vm_size_t size)
{
	vm_offset_t out_addr = UNLIKELY_INITIAL_ADDRESS;
	mach_msg_type_number_t out_size = UNLIKELY_INITIAL_SIZE;
	kern_return_t kr = vm_read(map, start, size, &out_addr, &out_size);
	if (kr == 0) {
		(void)mach_vm_deallocate(mach_task_self(), out_addr, out_size);
	}
	check_vm_read_outparam_changes(&kr, out_size, size, out_addr);
	return kr;
}
#endif

static kern_return_t
call_mach_vm_read_list(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	mach_vm_read_entry_t re = {{.address = start, .size = size}};
	kern_return_t kr = mach_vm_read_list(map, re, 1);
	if (kr == 0) {
		(void)mach_vm_deallocate(mach_task_self(), re[0].address, re[0].size);
	}
	return kr;
}
#if TEST_OLD_STYLE_MACH
static kern_return_t
call_vm_read_list(MAP_T map, vm_address_t start, vm_size_t size)
{
	vm_read_entry_t re = {{.address = start, .size = size}};
	kern_return_t kr = vm_read_list(map, re, 1);
	if (kr == 0) {
		(void)mach_vm_deallocate(mach_task_self(), re[0].address, re[0].size);
	}
	return kr;
}
#endif

static inline void
check_vm_read_overwrite_outparam_changes(kern_return_t * kr, mach_vm_size_t size, mach_vm_size_t requested_size)
{
	if (*kr == KERN_SUCCESS) {
		if (size != requested_size) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

static kern_return_t __unused
call_mach_vm_read_overwrite__ssz(MAP_T map, mach_vm_address_t start, mach_vm_address_t start_2, mach_vm_size_t size)
{
	mach_vm_size_t out_size;
	kern_return_t kr = mach_vm_read_overwrite(map, start, size, start_2, &out_size);
	check_vm_read_overwrite_outparam_changes(&kr, out_size, size);
	return kr;
}

static kern_return_t
call_mach_vm_read_overwrite__src(MAP_T map, mach_vm_address_t src, mach_vm_size_t size)
{
	mach_vm_size_t out_size;
	allocation_t dst SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = mach_vm_read_overwrite(map, src, size, dst.addr, &out_size);
	check_vm_read_overwrite_outparam_changes(&kr, out_size, size);
	return kr;
}

static kern_return_t
call_mach_vm_read_overwrite__dst(MAP_T map, mach_vm_address_t dst, mach_vm_size_t size)
{
	mach_vm_size_t out_size;
	allocation_t src SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = mach_vm_read_overwrite(map, src.addr, size, dst, &out_size);
	check_vm_read_overwrite_outparam_changes(&kr, out_size, size);
	return kr;
}

#if TEST_OLD_STYLE_MACH
static kern_return_t __unused
call_vm_read_overwrite__ssz(MAP_T map, vm_address_t start, vm_address_t start_2, vm_size_t size)
{
	vm_size_t out_size;
	kern_return_t kr = vm_read_overwrite(map, start, size, start_2, &out_size);
	check_vm_read_overwrite_outparam_changes(&kr, out_size, size);
	return kr;
}

static kern_return_t
call_vm_read_overwrite__src(MAP_T map, vm_address_t src, vm_size_t size)
{
	vm_size_t out_size;
	allocation_t dst SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = vm_read_overwrite(map, src, size, (vm_address_t) dst.addr, &out_size);
	check_vm_read_overwrite_outparam_changes(&kr, out_size, size);
	return kr;
}

static kern_return_t
call_vm_read_overwrite__dst(MAP_T map, vm_address_t dst, vm_size_t size)
{
	vm_size_t out_size;
	allocation_t src SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = vm_read_overwrite(map, (vm_address_t) src.addr, size, dst, &out_size);
	check_vm_read_overwrite_outparam_changes(&kr, out_size, size);
	return kr;
}
#endif



static kern_return_t __unused
call_mach_vm_copy__ssz(MAP_T map, mach_vm_address_t start, mach_vm_address_t start_2, mach_vm_size_t size)
{
	kern_return_t kr = mach_vm_copy(map, start, size, start_2);
	return kr;
}

static kern_return_t
call_mach_vm_copy__src(MAP_T map, mach_vm_address_t src, mach_vm_size_t size)
{
	allocation_t dst SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = mach_vm_copy(map, src, size, dst.addr);
	return kr;
}

static kern_return_t
call_mach_vm_copy__dst(MAP_T map, mach_vm_address_t dst, mach_vm_size_t size)
{
	allocation_t src SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = mach_vm_copy(map, src.addr, size, dst);
	return kr;
}

#if TEST_OLD_STYLE_MACH
static kern_return_t __unused
call_vm_copy__ssz(MAP_T map, mach_vm_address_t start, mach_vm_address_t start_2, mach_vm_size_t size)
{
	kern_return_t kr = vm_copy(map, (vm_address_t) start, (vm_size_t) size, (vm_address_t) start_2);
	return kr;
}

static kern_return_t
call_vm_copy__src(MAP_T map, vm_address_t src, vm_size_t size)
{
	allocation_t dst SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = vm_copy(map, src, size, (vm_address_t) dst.addr);
	return kr;
}

static kern_return_t
call_vm_copy__dst(MAP_T map, vm_address_t dst, vm_size_t size)
{
	allocation_t src SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = vm_copy(map, (vm_address_t) src.addr, size, dst);
	return kr;
}
#endif

static kern_return_t __unused
call_mach_vm_write__ssz(MAP_T map, mach_vm_address_t start, mach_vm_address_t start_2, mach_vm_size_t size)
{
	kern_return_t kr = mach_vm_write(map, start, (vm_offset_t) start_2, (mach_msg_type_number_t) size);
	return kr;
}

static kern_return_t
call_mach_vm_write__src(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	allocation_t dst SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = mach_vm_write(map, dst.addr, (vm_offset_t) start, (mach_msg_type_number_t) size);
	return kr;
}

static kern_return_t
call_mach_vm_write__dst(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	allocation_t src SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = mach_vm_write(map, start, (vm_offset_t) src.addr, (mach_msg_type_number_t) size);
	return kr;
}

#if TEST_OLD_STYLE_MACH
static kern_return_t __unused
call_vm_write__ssz(MAP_T map, mach_vm_address_t start, mach_vm_address_t start_2, mach_vm_size_t size)
{
	kern_return_t kr = vm_write(map, (vm_address_t) start, (vm_offset_t) start_2, (mach_msg_type_number_t) size);
	return kr;
}

static kern_return_t
call_vm_write__src(MAP_T map, vm_address_t start, vm_size_t size)
{
	allocation_t dst SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = vm_write(map, (vm_address_t) dst.addr, start, (mach_msg_type_number_t) size);
	return kr;
}

static kern_return_t
call_vm_write__dst(MAP_T map, vm_address_t start, vm_size_t size)
{
	allocation_t src SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = vm_write(map, start, (vm_offset_t) src.addr, (mach_msg_type_number_t) size);
	return kr;
}
#endif

// mach_vm_wire, vm_wire (start/size)
// "wire" and "unwire" paths diverge internally; test both
#define IMPL(FN, T, FLAVOR, PROT)                                       \
	static kern_return_t                                            \
	call_ ## FN ## __ ## FLAVOR(MAP_T map, T start, T size)         \
	{                                                               \
	        mach_port_t host_priv = HOST_PRIV_NULL;                 \
	        kern_return_t kr = host_get_host_priv_port(mach_host_self(), &host_priv); \
	        assert(kr == 0);  /* host priv port on macOS requires entitlements or root */ \
	        kr = FN(host_priv, map, start, size, PROT);             \
	        return kr;                                              \
	}
IMPL(mach_vm_wire, mach_vm_address_t, wire, VM_PROT_READ)
IMPL(mach_vm_wire, mach_vm_address_t, unwire, VM_PROT_NONE)
// The declaration of vm_wire is buggy on U32.
// We compile in our own MIG user stub for it with a "replacement_" prefix.
// rdar://118258929
IMPL(replacement_vm_wire, mach_vm_address_t, wire, VM_PROT_READ)
IMPL(replacement_vm_wire, mach_vm_address_t, unwire, VM_PROT_NONE)
#undef IMPL

// mach_vm_wire, vm_wire (vm_prot_t)
#define IMPL(FN, T)                                                     \
	static kern_return_t                                            \
	call_ ## FN ## __vm_prot(MAP_T map, T start, T size, vm_prot_t prot) \
	{                                                               \
	        mach_port_t host_priv = HOST_PRIV_NULL;                 \
	        kern_return_t kr = host_get_host_priv_port(mach_host_self(), &host_priv); \
	        assert(kr == 0);  /* host priv port on macOS requires entitlements or root */ \
	        kr = FN(host_priv, map, start, size, prot);             \
	        return kr;                                              \
	}
IMPL(mach_vm_wire, mach_vm_address_t)
// The declaration of vm_wire is buggy on U32.
// We compile in our own MIG user stub for it with a "replacement_" prefix.
// rdar://118258929
IMPL(replacement_vm_wire, mach_vm_address_t)
#undef IMPL


// mach_vm_map/vm32_map/vm32_map_64 infra

typedef kern_return_t (*map_fn_t)(vm_map_t target_task,
    mach_vm_address_t *address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    mem_entry_name_port_t object,
    memory_object_offset_t offset,
    boolean_t copy,
    vm_prot_t cur_protection,
    vm_prot_t max_protection,
    vm_inherit_t inheritance);

static kern_return_t
call_map_fn__allocate_fixed(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	mach_vm_address_t out_addr = start;
	kern_return_t kr = fn(map, &out_addr, size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
	    0, 0, 0, 0, 0, VM_INHERIT_NONE);
	// fixed-overwrite with pre-existing allocation, don't deallocate
	return kr;
}

static kern_return_t
call_map_fn__allocate_fixed_copy(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	mach_vm_address_t out_addr = start;
	kern_return_t kr = fn(map, &out_addr, size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
	    0, 0, true, 0, 0, VM_INHERIT_NONE);
	// fixed-overwrite with pre-existing allocation, don't deallocate
	return kr;
}

static kern_return_t
call_map_fn__allocate_anywhere(map_fn_t fn, MAP_T map, mach_vm_address_t start_hint, mach_vm_size_t size)
{
	mach_vm_address_t out_addr = start_hint;
	kern_return_t kr = fn(map, &out_addr, size, 0, VM_FLAGS_ANYWHERE, 0, 0, 0, 0, 0, VM_INHERIT_NONE);
	if (kr == 0) {
		(void)mach_vm_deallocate(map, out_addr, size);
	}
	return kr;
}

static kern_return_t
call_map_fn__memobject_fixed(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);
	mach_vm_address_t out_addr = start;
	kern_return_t kr = fn(map, &out_addr, size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
	    memobject, KB16, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	(void)mach_port_deallocate(mach_task_self(), memobject);
	// fixed-overwrite with pre-existing allocation, don't deallocate
	return kr;
}

static kern_return_t
call_map_fn__memobject_fixed_copy(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);
	mach_vm_address_t out_addr = start;
	kern_return_t kr = fn(map, &out_addr, size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
	    memobject, KB16, true, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	(void)mach_port_deallocate(mach_task_self(), memobject);
	// fixed-overwrite with pre-existing allocation, don't deallocate
	return kr;
}

static kern_return_t
call_map_fn__memobject_anywhere(map_fn_t fn, MAP_T map, mach_vm_address_t start_hint, mach_vm_size_t size)
{
	mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);
	mach_vm_address_t out_addr = start_hint;
	kern_return_t kr = fn(map, &out_addr, size, 0, VM_FLAGS_ANYWHERE, memobject,
	    KB16, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	if (kr == 0) {
		(void)mach_vm_deallocate(map, out_addr, size);
	}
	(void)mach_port_deallocate(mach_task_self(), memobject);
	return kr;
}

static kern_return_t
helper_call_map_fn__memobject__ssoo(map_fn_t fn, MAP_T map, int flags, bool copy, mach_vm_address_t start, mach_vm_size_t size, vm_object_offset_t offset, mach_vm_size_t obj_size)
{
	mach_port_t memobject = make_a_mem_object(obj_size);
	mach_vm_address_t out_addr = start;
	kern_return_t kr = fn(map, &out_addr, size, 0, flags, memobject,
	    offset, copy, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	deallocate_if_not_fixed_overwrite(kr, map, out_addr, size, flags);
	(void)mach_port_deallocate(mach_task_self(), memobject);
	return kr;
}

static kern_return_t
call_map_fn__memobject_fixed__start_size_offset_object(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_object_offset_t offset, mach_vm_size_t obj_size)
{
	return helper_call_map_fn__memobject__ssoo(fn, map, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, false, start, size, offset, obj_size);
}

static kern_return_t
call_map_fn__memobject_fixed_copy__start_size_offset_object(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_object_offset_t offset, mach_vm_size_t obj_size)
{
	return helper_call_map_fn__memobject__ssoo(fn, map, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, true, start, size, offset, obj_size);
}

static kern_return_t
call_map_fn__memobject_anywhere__start_size_offset_object(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_object_offset_t offset, mach_vm_size_t obj_size)
{
	return helper_call_map_fn__memobject__ssoo(fn, map, VM_FLAGS_ANYWHERE, false, start, size, offset, obj_size);
}

static kern_return_t
help_call_map_fn__allocate__inherit(map_fn_t fn, MAP_T map, int flags, bool copy, mach_vm_address_t start, mach_vm_size_t size, vm_inherit_t inherit)
{
	mach_vm_address_t out_addr = start;
	kern_return_t kr = fn(map, &out_addr, size, 0, flags,
	    0, KB16, copy, VM_PROT_DEFAULT, VM_PROT_DEFAULT, inherit);
	deallocate_if_not_fixed_overwrite(kr, map, out_addr, size, flags);
	return kr;
}

static kern_return_t
call_map_fn__allocate_fixed__inherit(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_inherit_t inherit)
{
	return help_call_map_fn__allocate__inherit(fn, map, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, false, start, size, inherit);
}

static kern_return_t
call_map_fn__allocate_fixed_copy__inherit(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_inherit_t inherit)
{
	return help_call_map_fn__allocate__inherit(fn, map, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, true, start, size, inherit);
}

static kern_return_t
call_map_fn__allocate_anywhere__inherit(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_inherit_t inherit)
{
	return help_call_map_fn__allocate__inherit(fn, map, VM_FLAGS_ANYWHERE, false, start, size, inherit);
}

static kern_return_t
help_call_map_fn__memobject__inherit(map_fn_t fn, MAP_T map, int flags, bool copy, mach_vm_address_t start, mach_vm_size_t size, vm_inherit_t inherit)
{
	mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);
	mach_vm_address_t out_addr = start;
	kern_return_t kr = fn(map, &out_addr, size, 0, flags,
	    memobject, KB16, copy, VM_PROT_DEFAULT, VM_PROT_DEFAULT, inherit);
	deallocate_if_not_fixed_overwrite(kr, map, out_addr, size, flags);
	(void)mach_port_deallocate(mach_task_self(), memobject);
	return kr;
}

static kern_return_t
call_map_fn__memobject_fixed__inherit(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_inherit_t inherit)
{
	return help_call_map_fn__memobject__inherit(fn, map, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, false, start, size, inherit);
}

static kern_return_t
call_map_fn__memobject_fixed_copy__inherit(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_inherit_t inherit)
{
	return help_call_map_fn__memobject__inherit(fn, map, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, true, start, size, inherit);
}

static kern_return_t
call_map_fn__memobject_anywhere__inherit(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_inherit_t inherit)
{
	return help_call_map_fn__memobject__inherit(fn, map, VM_FLAGS_ANYWHERE, false, start, size, inherit);
}

static kern_return_t
call_map_fn__allocate__flags(map_fn_t fn, MAP_T map, mach_vm_address_t * start, mach_vm_size_t size, int flags)
{
	kern_return_t kr = fn(map, start, size, 0, flags,
	    0, KB16, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	deallocate_if_not_fixed_overwrite(kr, map, *start, size, flags);
	return kr;
}

static kern_return_t
call_map_fn__allocate_copy__flags(map_fn_t fn, MAP_T map, mach_vm_address_t * start, mach_vm_size_t size, int flags)
{
	kern_return_t kr = fn(map, start, size, 0, flags,
	    0, KB16, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	deallocate_if_not_fixed_overwrite(kr, map, *start, size, flags);
	return kr;
}

static kern_return_t
call_map_fn__memobject__flags(map_fn_t fn, MAP_T map, mach_vm_address_t * start, mach_vm_size_t size, int flags)
{
	mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);
	kern_return_t kr = fn(map, start, size, 0, flags,
	    memobject, KB16, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	deallocate_if_not_fixed_overwrite(kr, map, *start, size, flags);
	(void)mach_port_deallocate(mach_task_self(), memobject);
	return kr;
}

static kern_return_t
call_map_fn__memobject_copy__flags(map_fn_t fn, MAP_T map, mach_vm_address_t * start, mach_vm_size_t size, int flags)
{
	mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);
	kern_return_t kr = fn(map, start, size, 0, flags,
	    memobject, KB16, true, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	deallocate_if_not_fixed_overwrite(kr, map, *start, size, flags);
	(void)mach_port_deallocate(mach_task_self(), memobject);
	return kr;
}

static kern_return_t
help_call_map_fn__allocate__prot_pairs(map_fn_t fn, MAP_T map, int flags, bool copy, vm_prot_t cur, vm_prot_t max)
{
	mach_vm_address_t out_addr = 0;
	kern_return_t kr = fn(map, &out_addr, KB16, 0, flags,
	    0, KB16, copy, cur, max, VM_INHERIT_DEFAULT);
	deallocate_if_not_fixed_overwrite(kr, map, out_addr, KB16, flags);
	return kr;
}

static kern_return_t
call_map_fn__allocate_fixed__prot_pairs(map_fn_t fn, MAP_T map, vm_prot_t cur, vm_prot_t max)
{
	return help_call_map_fn__allocate__prot_pairs(fn, map, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, false, cur, max);
}

static kern_return_t
call_map_fn__allocate_fixed_copy__prot_pairs(map_fn_t fn, MAP_T map, vm_prot_t cur, vm_prot_t max)
{
	return help_call_map_fn__allocate__prot_pairs(fn, map, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, true, cur, max);
}

static kern_return_t
call_map_fn__allocate_anywhere__prot_pairs(map_fn_t fn, MAP_T map, vm_prot_t cur, vm_prot_t max)
{
	return help_call_map_fn__allocate__prot_pairs(fn, map, VM_FLAGS_ANYWHERE, false, cur, max);
}

static kern_return_t
help_call_map_fn__memobject__prot_pairs(map_fn_t fn, MAP_T map, int flags, bool copy, vm_prot_t cur, vm_prot_t max)
{
	mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);
	mach_vm_address_t out_addr = 0;
	kern_return_t kr = fn(map, &out_addr, KB16, 0, flags,
	    memobject, KB16, copy, cur, max, VM_INHERIT_DEFAULT);
	deallocate_if_not_fixed_overwrite(kr, map, out_addr, KB16, flags);
	(void)mach_port_deallocate(mach_task_self(), memobject);
	return kr;
}

static kern_return_t
call_map_fn__memobject_fixed__prot_pairs(map_fn_t fn, MAP_T map, vm_prot_t cur, vm_prot_t max)
{
	return help_call_map_fn__memobject__prot_pairs(fn, map, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, false, cur, max);
}

static kern_return_t
call_map_fn__memobject_fixed_copy__prot_pairs(map_fn_t fn, MAP_T map, vm_prot_t cur, vm_prot_t max)
{
	return help_call_map_fn__memobject__prot_pairs(fn, map, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, true, cur, max);
}

static kern_return_t
call_map_fn__memobject_anywhere__prot_pairs(map_fn_t fn, MAP_T map, vm_prot_t cur, vm_prot_t max)
{
	return help_call_map_fn__memobject__prot_pairs(fn, map, VM_FLAGS_ANYWHERE, false, cur, max);
}

// implementations

#define IMPL_MAP_FN_START_SIZE(map_fn, instance)                                                \
    static kern_return_t                                                                        \
    call_ ## map_fn ## __ ## instance (MAP_T map, mach_vm_address_t start, mach_vm_size_t size) \
    {                                                                                           \
	return call_map_fn__ ## instance(map_fn, map, start, size);                             \
    }

#define IMPL_MAP_FN_HINT_SIZE(map_fn, instance)                                                      \
    static kern_return_t                                                                             \
    call_ ## map_fn ## __ ## instance (MAP_T map, mach_vm_address_t start_hint, mach_vm_size_t size) \
    {                                                                                                \
	return call_map_fn__ ## instance(map_fn, map, start_hint, size);                             \
    }

#define IMPL_MAP_FN_START_SIZE_OFFSET_OBJECT(map_fn, instance)                                                                                                                   \
    static kern_return_t                                                                                                                                                         \
    call_ ## map_fn ## __ ## instance ## __start_size_offset_object(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_object_offset_t offset, mach_vm_size_t obj_size) \
    {                                                                                                                                                                            \
	return call_map_fn__ ## instance ## __start_size_offset_object(map_fn, map, start, size, offset, obj_size);                                                              \
    }

#define IMPL_MAP_FN_START_SIZE_INHERIT(map_fn, instance)                                                                          \
    static kern_return_t                                                                                                          \
    call_ ## map_fn ## __ ## instance ## __inherit(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_inherit_t inherit) \
    {                                                                                                                             \
	return call_map_fn__ ## instance ## __inherit(map_fn, map, start, size, inherit);                                         \
    }

#define IMPL_MAP_FN_START_SIZE_FLAGS(map_fn, instance)                                                                 \
    static kern_return_t                                                                                               \
    call_ ## map_fn ## __ ## instance ## __flags(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size, int flags) \
    {                                                                                                                  \
	return call_map_fn__ ## instance ## __flags(map_fn, map, start, size, flags);                                  \
    }

#define IMPL_MAP_FN_PROT_PAIRS(map_fn, instance)                                               \
    static kern_return_t                                                                       \
    call_ ## map_fn ## __ ## instance ## __prot_pairs(MAP_T map, vm_prot_t cur, vm_prot_t max) \
    {                                                                                          \
	return call_map_fn__ ## instance ## __prot_pairs(map_fn, map, cur, max);               \
    }

#define IMPL(map_fn)                                                       \
	IMPL_MAP_FN_START_SIZE(map_fn, allocate_fixed)                     \
	IMPL_MAP_FN_START_SIZE(map_fn, allocate_fixed_copy)                \
	IMPL_MAP_FN_START_SIZE(map_fn, memobject_fixed)                    \
	IMPL_MAP_FN_START_SIZE(map_fn, memobject_fixed_copy)               \
	IMPL_MAP_FN_HINT_SIZE(map_fn, allocate_anywhere)                   \
	IMPL_MAP_FN_HINT_SIZE(map_fn, memobject_anywhere)                  \
	IMPL_MAP_FN_START_SIZE_OFFSET_OBJECT(map_fn, memobject_fixed)      \
	IMPL_MAP_FN_START_SIZE_OFFSET_OBJECT(map_fn, memobject_fixed_copy) \
	IMPL_MAP_FN_START_SIZE_OFFSET_OBJECT(map_fn, memobject_anywhere)   \
	IMPL_MAP_FN_START_SIZE_INHERIT(map_fn, allocate_fixed)             \
	IMPL_MAP_FN_START_SIZE_INHERIT(map_fn, allocate_fixed_copy)        \
	IMPL_MAP_FN_START_SIZE_INHERIT(map_fn, allocate_anywhere)          \
	IMPL_MAP_FN_START_SIZE_INHERIT(map_fn, memobject_fixed)            \
	IMPL_MAP_FN_START_SIZE_INHERIT(map_fn, memobject_fixed_copy)       \
	IMPL_MAP_FN_START_SIZE_INHERIT(map_fn, memobject_anywhere)         \
	IMPL_MAP_FN_START_SIZE_FLAGS(map_fn, allocate)                     \
	IMPL_MAP_FN_START_SIZE_FLAGS(map_fn, allocate_copy)                \
	IMPL_MAP_FN_START_SIZE_FLAGS(map_fn, memobject)                    \
	IMPL_MAP_FN_START_SIZE_FLAGS(map_fn, memobject_copy)               \
	IMPL_MAP_FN_PROT_PAIRS(map_fn, allocate_fixed)                     \
	IMPL_MAP_FN_PROT_PAIRS(map_fn, allocate_fixed_copy)                \
	IMPL_MAP_FN_PROT_PAIRS(map_fn, allocate_anywhere)                  \
	IMPL_MAP_FN_PROT_PAIRS(map_fn, memobject_fixed)                    \
	IMPL_MAP_FN_PROT_PAIRS(map_fn, memobject_fixed_copy)               \
	IMPL_MAP_FN_PROT_PAIRS(map_fn, memobject_anywhere)                 \

static kern_return_t
mach_vm_map_wrapped(vm_map_t target_task,
    mach_vm_address_t *address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    mem_entry_name_port_t object,
    memory_object_offset_t offset,
    boolean_t copy,
    vm_prot_t cur_protection,
    vm_prot_t max_protection,
    vm_inherit_t inheritance)
{
	mach_vm_address_t addr = *address;
	kern_return_t kr = mach_vm_map(target_task, &addr, size, mask, flags, object, offset, copy, cur_protection, max_protection, inheritance);
	check_mach_vm_map_outparam_changes(&kr, addr, *address, flags, target_task);
	*address = addr;
	return kr;
}
IMPL(mach_vm_map_wrapped)

#if TEST_OLD_STYLE_MACH
static kern_return_t
vm_map_64_retyped(vm_map_t target_task,
    mach_vm_address_t *address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    mem_entry_name_port_t object,
    memory_object_offset_t offset,
    boolean_t copy,
    vm_prot_t cur_protection,
    vm_prot_t max_protection,
    vm_inherit_t inheritance)
{
	vm_address_t addr = (vm_address_t)*address;
	kern_return_t kr = vm_map_64(target_task, &addr, (vm_size_t)size, (vm_address_t)mask, flags, object, (vm_offset_t)offset, copy, cur_protection, max_protection, inheritance);
	check_mach_vm_map_outparam_changes(&kr, addr, (vm_address_t)*address, flags, target_task);
	*address = addr;
	return kr;
}
IMPL(vm_map_64_retyped)

static kern_return_t
vm_map_retyped(vm_map_t target_task,
    mach_vm_address_t *address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    mem_entry_name_port_t object,
    memory_object_offset_t offset,
    boolean_t copy,
    vm_prot_t cur_protection,
    vm_prot_t max_protection,
    vm_inherit_t inheritance)
{
	vm_address_t addr = (vm_address_t)*address;
	kern_return_t kr = vm_map(target_task, &addr, (vm_size_t)size, (vm_address_t)mask, flags, object, (vm_offset_t)offset, copy, cur_protection, max_protection, inheritance);
	check_mach_vm_map_outparam_changes(&kr, addr, (vm_address_t)*address, flags, target_task);
	*address = addr;
	return kr;
}
IMPL(vm_map_retyped)
#endif

#undef IMPL_MAP_FN_START_SIZE
#undef IMPL_MAP_FN_SIZE
#undef IMPL_MAP_FN_START_SIZE_OFFSET_OBJECT
#undef IMPL_MAP_FN_START_SIZE_INHERIT
#undef IMPL_MAP_FN_START_SIZE_FLAGS
#undef IMPL_MAP_FN_PROT_PAIRS
#undef IMPL


// mmap
// Directly calling this symbol lets us hit the syscall directly instead of the libsyscall wrapper.
void *__mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);

// We invert MAP_UNIX03 in the flags. This is because by default libsyscall intercepts calls to mmap and adds MAP_UNIX03.
// That means MAP_UNIX03 should be the default for most of our tests, and we should only test without MAP_UNIX03 when we explicitly want to.
void *
mmap_wrapper(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
	flags ^= MAP_UNIX03;
	return __mmap(addr, len, prot, flags, fildes, off);
}

// Rename the UNIX03 flag for the code below since we're inverting its meaning.
#define MAP_NOT_UNIX03 0x40000
static_assert(MAP_NOT_UNIX03 == MAP_UNIX03, "MAP_UNIX03 value changed");
#undef MAP_UNIX03
#define MAP_UNIX03 dont_use_MAP_UNIX03

// helpers

// Return true if security policy disallows unsigned code.
// Some test results are expected to change with this set.
static bool
unsigned_code_is_disallowed(void)
{
	if (isRosetta()) {
		return false;
	}

	int out_value = 0;
	size_t io_size = sizeof(out_value);
	if (0 == sysctlbyname("security.mac.amfi.unsigned_code_policy",
	    &out_value, &io_size, NULL, 0)) {
		return out_value;
	}

	// sysctl not present, assume unsigned code is okay
	return false;
}

static int
maybe_hide_mmap_failure(int ret, int prot, int fd)
{
	// Special case for mmap(PROT_EXEC, fd).
	// When SIP is enabled these get EPERM from mac_file_check_mmap().
	// The golden files record the SIP-disabled values.
	// This special case also allows the test to succeed when SIP
	// is enabled even though the return value isn't the golden one.
	if (ret == EPERM && fd != -1 && (prot & PROT_EXEC) &&
	    unsigned_code_is_disallowed()) {
		return ACCEPTABLE;
	}
	return ret;
}

static kern_return_t
help_call_mmap__vm_prot(MAP_T map __unused, int flags, mach_vm_address_t start, mach_vm_size_t size, vm_prot_t prot)
{
	int fd = -1;
	if (!(flags & MAP_ANON)) {
		fd = get_fd();
	}
	void *rv = mmap_wrapper((void *)start, (size_t) size, prot, flags, fd, 0);
	if (rv == MAP_FAILED) {
		return maybe_hide_mmap_failure(errno, prot, fd);
	} else {
		assert(0 == munmap_helper(rv, size));
		return 0;
	}
}

static kern_return_t
help_call_mmap__kernel_flags(MAP_T map __unused, int mmap_flags, mach_vm_address_t start, mach_vm_size_t size, int kernel_flags)
{
	void *rv = mmap_wrapper((void *)start, (size_t) size, VM_PROT_DEFAULT, mmap_flags, kernel_flags, 0);
	if (rv == MAP_FAILED) {
		return errno;
	} else {
		assert(0 == munmap_helper(rv, size));
		return 0;
	}
}

static kern_return_t
help_call_mmap__dst_size_fileoff(MAP_T map __unused, int flags, mach_vm_address_t dst, mach_vm_size_t size, mach_vm_address_t fileoff)
{
	int fd = -1;
	if (!(flags & MAP_ANON)) {
		fd = get_fd();
	}
	void *rv = mmap_wrapper((void *)dst, (size_t) size, VM_PROT_DEFAULT, flags, fd, (off_t)fileoff);
	if (rv == MAP_FAILED) {
		return errno;
	} else {
		assert(0 == munmap_helper(rv, size));
		return 0;
	}
}

static kern_return_t
help_call_mmap__start_size(MAP_T map __unused, int flags, mach_vm_address_t start, mach_vm_size_t size)
{
	int fd = -1;
	if (!(flags & MAP_ANON)) {
		fd = get_fd();
	}
	void *rv = mmap_wrapper((void *)start, (size_t) size, VM_PROT_DEFAULT, flags, fd, 0);
	if (rv == MAP_FAILED) {
		return errno;
	} else {
		assert(0 == munmap_helper(rv, size));
		return 0;
	}
}

static kern_return_t
help_call_mmap__offset_size(MAP_T map __unused, int flags, mach_vm_address_t offset, mach_vm_size_t size)
{
	int fd = -1;
	if (!(flags & MAP_ANON)) {
		fd = get_fd();
	}
	void *rv = mmap_wrapper((void *)0, (size_t) size, VM_PROT_DEFAULT, flags, fd, (off_t)offset);
	if (rv == MAP_FAILED) {
		return errno;
	} else {
		assert(0 == munmap_helper(rv, size));
		return 0;
	}
}

#define IMPL_ONE_FROM_HELPER(type, variant, flags, ...)                                                                                 \
	static kern_return_t                                                                                                            \
	__attribute__((used))                                                                                                           \
	call_mmap ## __ ## variant ## __ ## type(MAP_T map, mach_vm_address_t start, mach_vm_size_t size DROP_COMMAS(__VA_ARGS__)) {    \
	        return help_call_mmap__ ## type(map, flags, start, size DROP_TYPES(__VA_ARGS__));                                       \
	}

// call functions

#define IMPL_FROM_HELPER(type, ...) \
	IMPL_ONE_FROM_HELPER(type, file_private,          MAP_FILE | MAP_PRIVATE,                          ##__VA_ARGS__)  \
	IMPL_ONE_FROM_HELPER(type, anon_private,          MAP_ANON | MAP_PRIVATE,                          ##__VA_ARGS__)  \
	IMPL_ONE_FROM_HELPER(type, file_shared,           MAP_FILE | MAP_SHARED,                           ##__VA_ARGS__)  \
	IMPL_ONE_FROM_HELPER(type, anon_shared,           MAP_ANON | MAP_SHARED,                           ##__VA_ARGS__)  \
	IMPL_ONE_FROM_HELPER(type, file_private_codesign, MAP_FILE | MAP_PRIVATE | MAP_RESILIENT_CODESIGN, ##__VA_ARGS__)  \
	IMPL_ONE_FROM_HELPER(type, file_private_media,    MAP_FILE | MAP_PRIVATE | MAP_RESILIENT_MEDIA,    ##__VA_ARGS__)  \
	IMPL_ONE_FROM_HELPER(type, nounix03_private,      MAP_FILE | MAP_PRIVATE | MAP_NOT_UNIX03,         ##__VA_ARGS__)  \
	IMPL_ONE_FROM_HELPER(type, fixed_private,         MAP_FILE | MAP_PRIVATE | MAP_FIXED,              ##__VA_ARGS__)  \

IMPL_FROM_HELPER(vm_prot, vm_prot_t, prot)
IMPL_FROM_HELPER(dst_size_fileoff, mach_vm_address_t, fileoff)
IMPL_FROM_HELPER(start_size)
IMPL_FROM_HELPER(offset_size)

IMPL_ONE_FROM_HELPER(kernel_flags, anon_private, MAP_ANON | MAP_PRIVATE, int, kernel_flags)
IMPL_ONE_FROM_HELPER(kernel_flags, anon_shared, MAP_ANON | MAP_SHARED, int, kernel_flags)

static kern_return_t
call_mmap__mmap_flags(MAP_T map __unused, mach_vm_address_t start, mach_vm_size_t size, int mmap_flags)
{
	int fd = -1;
	if (!(mmap_flags & MAP_ANON)) {
		fd = get_fd();
	}
	void *rv = mmap_wrapper((void *)start, (size_t) size, VM_PROT_DEFAULT, mmap_flags, fd, 0);
	if (rv == MAP_FAILED) {
		return errno;
	} else {
		assert(0 == munmap(rv, (size_t) size));
		return 0;
	}
}

// Mach memory entry ownership

static kern_return_t
call_mach_memory_entry_ownership__ledger_tag(MAP_T map __unused, int ledger_tag)
{
	mach_port_t mementry = make_a_mem_entry(TEST_ALLOC_SIZE + 1);
	kern_return_t kr = mach_memory_entry_ownership(mementry, mach_task_self(), ledger_tag, 0);
	(void)mach_port_deallocate(mach_task_self(), mementry);
	return kr;
}

static kern_return_t
call_mach_memory_entry_ownership__ledger_flag(MAP_T map __unused, int ledger_flag)
{
	mach_port_t mementry = make_a_mem_entry(TEST_ALLOC_SIZE + 1);
	kern_return_t kr = mach_memory_entry_ownership(mementry, mach_task_self(), VM_LEDGER_TAG_DEFAULT, ledger_flag);
	(void)mach_port_deallocate(mach_task_self(), mementry);
	return kr;
}


// For deallocators like munmap and vm_deallocate.
// Return a non-zero error code if we should avoid performing this trial.
kern_return_t
short_circuit_deallocator(MAP_T map, start_size_trial_t trial)
{
	// mach_vm_deallocate(size == 0) is safe
	if (trial.size == 0) {
		return 0;
	}

	// Allow deallocation attempts based on a valid allocation
	// (assumes the test loop will slide this trial to a valid allocation)
	if (!trial.start_is_absolute && trial.size_is_absolute) {
		return 0;
	}

	// Avoid overwriting random live memory.
	if (!vm_sanitize_range_overflows_strict_zero(trial.start, trial.size, VM_MAP_PAGE_MASK(map))) {
		return IGNORED;
	}

	// Avoid EXC_GUARD if it is still enabled.
	mach_vm_address_t sum;
	if (!__builtin_add_overflow(trial.start, trial.size, &sum) &&
	    trial.start + trial.size != 0 &&
	    round_up_page(trial.start + trial.size, PAGE_SIZE) == 0) {
		// this case provokes EXC_GUARD
		if (EXC_GUARD_ENABLED) {
			return GUARD;
		}
	}

	// Allow.
	return 0;
}

static kern_return_t
call_mach_vm_deallocate(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	kern_return_t kr = mach_vm_deallocate(map, start, size);
	return kr;
}

#if TEST_OLD_STYLE_MACH
static kern_return_t
call_vm_deallocate(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	kern_return_t kr = vm_deallocate(map, (vm_address_t) start, (vm_size_t) size);
	return kr;
}
#endif

static kern_return_t
call_mach_vm_allocate__flags(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size, int flags)
{
	mach_vm_address_t saved_start = *start;
	kern_return_t kr = mach_vm_allocate(map, start, size, flags);
	check_mach_vm_allocate_outparam_changes(&kr, *start, size, saved_start, flags, map);
	return kr;
}


static kern_return_t
call_mach_vm_allocate__start_size_fixed(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size)
{
	mach_vm_address_t saved_start = *start;
	kern_return_t kr = mach_vm_allocate(map, start, size, VM_FLAGS_FIXED);
	check_mach_vm_allocate_outparam_changes(&kr, *start, size, saved_start, VM_FLAGS_FIXED, map);
	return kr;
}

static kern_return_t
call_mach_vm_allocate__start_size_anywhere(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size)
{
	mach_vm_address_t saved_start = *start;
	kern_return_t kr = mach_vm_allocate(map, start, size, VM_FLAGS_ANYWHERE);
	check_mach_vm_allocate_outparam_changes(&kr, *start, size, saved_start, VM_FLAGS_ANYWHERE, map);
	return kr;
}

static kern_return_t
call_mach_vm_inherit(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	kern_return_t kr = mach_vm_inherit(map, start, size, VM_INHERIT_NONE);
	return kr;
}
#if TEST_OLD_STYLE_MACH
static kern_return_t
call_vm_inherit(MAP_T map, vm_address_t start, vm_size_t size)
{
	kern_return_t kr = vm_inherit(map, start, size, VM_INHERIT_NONE);
	return kr;
}
#endif

static int
call_minherit(void *start, size_t size)
{
	int err = minherit(start, size, VM_INHERIT_SHARE);
	return err ? errno : 0;
}

static kern_return_t
call_mach_vm_inherit__inherit(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_inherit_t value)
{
	kern_return_t kr = mach_vm_inherit(map, start, size, value);
	return kr;
}

static int
call_minherit__inherit(void * start, size_t size, int value)
{
	int err = minherit(start, size, value);
	return err ? errno : 0;
}

static kern_return_t
call_mach_vm_protect__start_size(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	kern_return_t kr = mach_vm_protect(map, start, size, 0, VM_PROT_READ | VM_PROT_WRITE);
	return kr;
}
static kern_return_t
call_mach_vm_protect__vm_prot(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_prot_t prot)
{
	kern_return_t kr = mach_vm_protect(map, start, size, 0, prot);
	return kr;
}
#if TEST_OLD_STYLE_MACH
static kern_return_t
call_vm_protect__start_size(MAP_T map, vm_address_t start, vm_size_t size)
{
	kern_return_t kr = vm_protect(map, start, size, 0, VM_PROT_READ | VM_PROT_WRITE);
	return kr;
}
static kern_return_t
call_vm_protect__vm_prot(MAP_T map, vm_address_t start, vm_size_t size, vm_prot_t prot)
{
	kern_return_t kr = vm_protect(map, start, size, 0, prot);
	return kr;
}
#endif

extern int __mprotect(void *, size_t, int);

static int
call_mprotect__start_size(void *start, size_t size)
{
	int err = __mprotect(start, size, PROT_READ | PROT_WRITE);
	return err ? errno : 0;
}

static int
call_mprotect__vm_prot(void *start, size_t size, int prot)
{
	int err = __mprotect(start, size, prot);
	return err ? errno : 0;
}

#if TEST_OLD_STYLE_MACH
static kern_return_t
call_vm_behavior_set__start_size__default(MAP_T map, vm_address_t start, vm_size_t size)
{
	kern_return_t kr = vm_behavior_set(map, start, size, VM_BEHAVIOR_DEFAULT);
	return kr;
}

static kern_return_t
call_vm_behavior_set__start_size__can_reuse(MAP_T map, vm_address_t start, vm_size_t size)
{
	kern_return_t kr = vm_behavior_set(map, start, size, VM_BEHAVIOR_CAN_REUSE);
	return kr;
}

static kern_return_t
call_vm_behavior_set__vm_behavior(MAP_T map, vm_address_t start, vm_size_t size, vm_behavior_t behavior)
{
	kern_return_t kr = vm_behavior_set(map, start, size, behavior);
	return kr;
}
#endif /* TEST_OLD_STYLE_MACH */

extern int __shared_region_map_and_slide_2_np(uint32_t files_count,
    const struct shared_file_np *files,
    uint32_t mappings_count,
    const struct shared_file_mapping_slide_np *mappings);

static int
maybe_hide_shared_region_map_failure(int ret,
    uint32_t files_count, const struct shared_file_np *files,
    uint32_t mappings_count)
{
	// Special case for __shared_region_map_and_slide_2_np().
	// When SIP is enabled this case gets EPERM instead of EINVAL due to
	// vm_shared_region_map_file returning KERN_PROTECTION_FAILURE instead of
	// KERN_INVALID_ARGUMENT.
	if (ret == EPERM && files_count == 1 && mappings_count == 1 &&
	    files->sf_fd == get_fd() && files->sf_mappings_count == 1 &&
	    unsigned_code_is_disallowed()) {
		return ACCEPTABLE;
	}
	return ret;
}

static int
call_shared_region_map_and_slide_2_np_child(uint32_t files_count, const struct shared_file_np *files,
    uint32_t mappings_count, const struct shared_file_mapping_slide_np *mappings)
{
	int err = __shared_region_map_and_slide_2_np(files_count, files, mappings_count, mappings);
	return err ? maybe_hide_shared_region_map_failure(errno, files_count, files, mappings_count) : 0;
}

typedef struct {
	uint32_t files_count;
	const struct shared_file_np *files;
	uint32_t mappings_count;
	const struct shared_file_mapping_slide_np *mappings;
} map_n_slice_thread_args;

void*
thread_func(void* args)
{
	map_n_slice_thread_args *thread_args = (map_n_slice_thread_args *)args;
	uint32_t files_count = thread_args->files_count;
	const struct shared_file_np *files = thread_args->files;
	uint32_t mappings_count = thread_args->mappings_count;
	const struct shared_file_mapping_slide_np *mappings = thread_args->mappings;

	int err = call_shared_region_map_and_slide_2_np_child(files_count, files, mappings_count, mappings);

	int *result = malloc(sizeof(int));
	assert(result != NULL);
	*result = err;
	return result;
}

static int
call_shared_region_map_and_slide_2_np_in_thread(uint32_t files_count, const struct shared_file_np *files,
    uint32_t mappings_count, const struct shared_file_mapping_slide_np *mappings)
{
	// From vm/vm_shared_region.c: After a chroot(), the calling process keeps using its original shared region [...]
	// But its children will use a different shared region [...]
	if (chroot(".") < 0) {
		return BUSTED;
	}

	map_n_slice_thread_args args = {files_count, files, mappings_count, mappings};
	pthread_t thread;
	if (pthread_create(&thread, NULL, thread_func, (void *)&args) < 0) {
		return -91;
	}

	int *err;
	if (pthread_join(thread, (void**)&err) < 0) {
		return BUSTED;
	}

	if (chroot("/") < 0) {
		return BUSTED;
	}

	return *err;
}

static int
call_madvise__start_size(void *start, size_t size)
{
	int err = madvise(start, size, MADV_NORMAL);
	return err ? errno : 0;
}

static int
call_madvise__vm_advise(void *start, size_t size, int advise)
{
	int err = madvise(start, size, advise);
	return err ? errno : 0;
}

static int
call_mach_vm_msync__start_size(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	kern_return_t kr = mach_vm_msync(map, start, size, VM_SYNC_ASYNCHRONOUS);
	return kr;
}

static int
call_mach_vm_msync__vm_sync(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_sync_t sync)
{
	kern_return_t kr = mach_vm_msync(map, start, size, sync);
	return kr;
}

#if TEST_OLD_STYLE_MACH
static int
call_vm_msync__start_size(MAP_T map, vm_address_t start, vm_size_t size)
{
	kern_return_t kr = vm_msync(map, start, size, VM_SYNC_ASYNCHRONOUS);
	return kr;
}

static int
call_vm_msync__vm_sync(MAP_T map, vm_address_t start, vm_size_t size, vm_sync_t sync)
{
	kern_return_t kr = vm_msync(map, start, size, sync);
	return kr;
}
#endif /* TEST_OLD_STYLE_MACH */

// msync has a libsyscall wrapper that does alignment. We want the raw syscall.
int __msync(void *, size_t, int);

static int
call_msync__start_size(void *start, size_t size)
{
	int err = __msync(start, size, MS_SYNC);
	return err ? errno : 0;
}

static int
call_msync__vm_msync(void *start, size_t size, int msync_value)
{
	int err = __msync(start, size, msync_value);
	return err ? errno : 0;
}

// msync nocancel isn't declared, but we want to directly hit the syscall
int __msync_nocancel(void *, size_t, int);

static int
call_msync_nocancel__start_size(void *start, size_t size)
{
	int err = __msync_nocancel(start, size, MS_SYNC);
	return err ? errno : 0;
}

static int
call_msync_nocancel__vm_msync(void *start, size_t size, int msync_value)
{
	int err = __msync_nocancel(start, size, msync_value);
	return err ? errno : 0;
}

static void
check_mach_vm_machine_attribute_outparam_changes(kern_return_t * kr, vm_machine_attribute_val_t value, vm_machine_attribute_val_t saved_value)
{
	if (value != saved_value) {
		*kr = OUT_PARAM_BAD;
	}
}

static int
call_mach_vm_machine_attribute__start_size(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	vm_machine_attribute_val_t value = MATTR_VAL_GET;
	vm_machine_attribute_val_t initial_value = value;
	kern_return_t kr = mach_vm_machine_attribute(map, start, size, MATTR_CACHE, &value);
	check_mach_vm_machine_attribute_outparam_changes(&kr, value, initial_value);
	return kr;
}


static int
call_mach_vm_machine_attribute__machine_attribute(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_machine_attribute_t attr)
{
	vm_machine_attribute_val_t value = MATTR_VAL_GET;
	vm_machine_attribute_val_t initial_value = value;
	kern_return_t kr = mach_vm_machine_attribute(map, start, size, attr, &value);
	check_mach_vm_machine_attribute_outparam_changes(&kr, value, initial_value);
	return kr;
}

#if TEST_OLD_STYLE_MACH
static int
call_vm_machine_attribute__start_size(MAP_T map, vm_address_t start, vm_size_t size)
{
	vm_machine_attribute_val_t value = MATTR_VAL_GET;
	vm_machine_attribute_val_t initial_value = value;
	kern_return_t kr = vm_machine_attribute(map, start, size, MATTR_CACHE, &value);
	check_mach_vm_machine_attribute_outparam_changes(&kr, value, initial_value);
	return kr;
}

static int
call_vm_machine_attribute__machine_attribute(MAP_T map, vm_address_t start, vm_size_t size, vm_machine_attribute_t attr)
{
	vm_machine_attribute_val_t value = MATTR_VAL_GET;
	vm_machine_attribute_val_t initial_value = value;
	kern_return_t kr = vm_machine_attribute(map, start, size, attr, &value);
	check_mach_vm_machine_attribute_outparam_changes(&kr, value, initial_value);
	return kr;
}
#endif /* TEST_OLD_STYLE_MACH */

static int
call_mach_vm_purgable_control__address__get(MAP_T map, mach_vm_address_t addr)
{
	int state = INVALID_PURGABLE_STATE;
	int initial_state = state;
	kern_return_t kr = mach_vm_purgable_control(map, addr, VM_PURGABLE_GET_STATE, &state);
	check_mach_vm_purgable_control_outparam_changes(&kr, state, initial_state, VM_PURGABLE_GET_STATE);
	return kr;
}


static int
call_mach_vm_purgable_control__address__purge_all(MAP_T map, mach_vm_address_t addr)
{
	int state = INVALID_PURGABLE_STATE;
	int initial_state = state;
	kern_return_t kr = mach_vm_purgable_control(map, addr, VM_PURGABLE_PURGE_ALL, &state);
	check_mach_vm_purgable_control_outparam_changes(&kr, state, initial_state, VM_PURGABLE_PURGE_ALL);
	return kr;
}

static int
call_mach_vm_purgable_control__purgeable_state(MAP_T map, mach_vm_address_t addr, vm_purgable_t control, int state)
{
	int initial_state = state;
	kern_return_t kr = mach_vm_purgable_control(map, addr, control, &state);
	check_mach_vm_purgable_control_outparam_changes(&kr, state, initial_state, control);
	return kr;
}

#if TEST_OLD_STYLE_MACH
static int
call_vm_purgable_control__address__get(MAP_T map, vm_address_t addr)
{
	int state = INVALID_PURGABLE_STATE;
	int initial_state = state;
	kern_return_t kr = vm_purgable_control(map, addr, VM_PURGABLE_GET_STATE, &state);
	check_mach_vm_purgable_control_outparam_changes(&kr, state, initial_state, VM_PURGABLE_GET_STATE);
	return kr;
}

static int
call_vm_purgable_control__address__purge_all(MAP_T map, vm_address_t addr)
{
	int state = INVALID_PURGABLE_STATE;
	int initial_state = state;
	kern_return_t kr = vm_purgable_control(map, addr, VM_PURGABLE_PURGE_ALL, &state);
	check_mach_vm_purgable_control_outparam_changes(&kr, state, initial_state, VM_PURGABLE_PURGE_ALL);
	return kr;
}

static int
call_vm_purgable_control__purgeable_state(MAP_T map, vm_address_t addr, vm_purgable_t control, int state)
{
	int initial_state = state;
	kern_return_t kr = vm_purgable_control(map, addr, control, &state);
	check_mach_vm_purgable_control_outparam_changes(&kr, state, initial_state, control);
	return kr;
}
#endif /* TEST_OLD_STYLE_MACH */

static void
check_mach_vm_region_recurse_outparam_changes(kern_return_t * kr, void * info, void * saved_info, size_t info_size,
    natural_t depth, natural_t saved_depth, mach_vm_address_t addr, mach_vm_address_t saved_addr,
    mach_vm_size_t size, mach_vm_size_t saved_size)
{
	if (*kr == KERN_SUCCESS) {
		if (depth == saved_depth) {
			*kr = OUT_PARAM_BAD;
		}
		if (size == saved_size) {
			*kr = OUT_PARAM_BAD;
		}
		if (memcmp(info, saved_info, info_size) == 0) {
			*kr = OUT_PARAM_BAD;
		}
	} else {
		if (depth != saved_depth || addr != saved_addr || size != saved_size || memcmp(info, saved_info, info_size) != 0) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

static kern_return_t
call_mach_vm_region_recurse(MAP_T map, mach_vm_address_t addr)
{
	vm_region_submap_info_data_64_t info;
	info.inheritance = INVALID_INHERIT;
	vm_region_submap_info_data_64_t saved_info = info;
	mach_vm_size_t size_out = UNLIKELY_INITIAL_SIZE;
	mach_vm_size_t saved_size = size_out;
	natural_t depth = 10;
	natural_t saved_depth = depth;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
	mach_vm_address_t addr_cpy = addr;

	kern_return_t kr = mach_vm_region_recurse(map,
	    &addr_cpy,
	    &size_out,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	check_mach_vm_region_recurse_outparam_changes(&kr, &info, &saved_info, sizeof(info), depth, saved_depth,
	    addr, addr_cpy, size_out, saved_size);

	return kr;
}

#if TEST_OLD_STYLE_MACH
static kern_return_t
call_vm_region_recurse(MAP_T map, vm_address_t addr)
{
	vm_region_submap_info_data_t info;
	info.inheritance = INVALID_INHERIT;
	vm_region_submap_info_data_t saved_info = info;

	vm_size_t size_out = UNLIKELY_INITIAL_SIZE;
	vm_size_t saved_size = size_out;

	natural_t depth = 10;
	natural_t saved_depth = depth;

	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT;
	vm_address_t addr_cpy = addr;

	kern_return_t kr = vm_region_recurse(map,
	    &addr_cpy,
	    &size_out,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);

	check_mach_vm_region_recurse_outparam_changes(&kr, &info, &saved_info, sizeof(info), depth, saved_depth,
	    addr_cpy, addr, size_out, saved_size);

	return kr;
}

static kern_return_t
call_vm_region_recurse_64(MAP_T map, vm_address_t addr)
{
	vm_region_submap_info_data_64_t info;
	info.inheritance = INVALID_INHERIT;
	vm_region_submap_info_data_64_t saved_info = info;

	vm_size_t size_out = UNLIKELY_INITIAL_SIZE;
	vm_size_t saved_size = size_out;

	natural_t depth = 10;
	natural_t saved_depth = depth;

	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
	vm_address_t addr_cpy = addr;

	kern_return_t kr = vm_region_recurse_64(map,
	    &addr_cpy,
	    &size_out,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);

	check_mach_vm_region_recurse_outparam_changes(&kr, &info, &saved_info, sizeof(info), depth, saved_depth,
	    addr_cpy, addr, size_out, saved_size);

	return kr;
}
#endif /* TEST_OLD_STYLE_MACH */

static kern_return_t
call_mach_vm_page_info(MAP_T map, mach_vm_address_t addr)
{
	vm_page_info_flavor_t flavor = VM_PAGE_INFO_BASIC;
	mach_msg_type_number_t count = VM_PAGE_INFO_BASIC_COUNT;
	mach_msg_type_number_t saved_count = count;
	vm_page_info_basic_data_t info = {0};
	info.depth = -1;
	vm_page_info_basic_data_t saved_info = info;

	kern_return_t kr = mach_vm_page_info(map, addr, flavor, (vm_page_info_t)&info, &count);
	check_mach_vm_page_info_outparam_changes(&kr, info, saved_info, count, saved_count);
	return kr;
}

static void
check_mach_vm_page_query_outparam_changes(kern_return_t * kr, int disposition, int saved_disposition, int ref_count)
{
	if (*kr == KERN_SUCCESS) {
		/*
		 * There should be no outside references to the memory created for this test
		 */
		if (ref_count != 0) {
			*kr = OUT_PARAM_BAD;
		}
		if (disposition == saved_disposition) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

static kern_return_t
call_mach_vm_page_query(MAP_T map, mach_vm_address_t addr)
{
	int disp = INVALID_DISPOSITION_VALUE, ref = 0;
	int saved_disposition = disp;
	kern_return_t kr = mach_vm_page_query(map, addr, &disp, &ref);
	check_mach_vm_page_query_outparam_changes(&kr, disp, saved_disposition, ref);
	return kr;
}

#if TEST_OLD_STYLE_MACH
static kern_return_t
call_vm_map_page_query(MAP_T map, vm_address_t addr)
{
	int disp = INVALID_DISPOSITION_VALUE, ref = 0;
	int saved_disposition = disp;
	kern_return_t kr = vm_map_page_query(map, addr, &disp, &ref);
	check_mach_vm_page_query_outparam_changes(&kr, disp, saved_disposition, ref);
	return kr;
}
#endif /* TEST_OLD_STYLE_MACH */

static void
check_mach_vm_page_range_query_outparam_changes(kern_return_t * kr, mach_vm_size_t out_count, mach_vm_size_t in_count)
{
	if (out_count != in_count) {
		*kr = OUT_PARAM_BAD;
	}
}

static kern_return_t
call_mach_vm_page_range_query(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	// mach_vm_page_range_query writes one int per page output
	// and can accept any address range as input
	// We can't provide that much storage for very large lengths.
	// Instead we provide a limited output buffer,
	// write-protect the page after it, and "succeed" if the kernel
	// fills the buffer and then returns EFAULT.

	// enough space for MAX_PAGE_RANGE_QUERY with 4KB pages, twice
	mach_vm_size_t prq_buf_size = 2 * 262144 * sizeof(int);
	mach_vm_address_t prq_buf = 0;
	kern_return_t kr = mach_vm_allocate(map, &prq_buf,
	    prq_buf_size + KB16, VM_FLAGS_ANYWHERE);
	assert(kr == 0);

	// protect the guard page
	mach_vm_address_t prq_guard = prq_buf + prq_buf_size;
	kr = mach_vm_protect(map, prq_guard, KB16, 0, VM_PROT_NONE);
	assert(kr == 0);

	// pre-fill the output buffer with an invalid value
	memset((char *)prq_buf, 0xff, prq_buf_size);

	mach_vm_size_t in_count = size / KB16 + (size % KB16 ? 1 : 0);
	mach_vm_size_t out_count = in_count;
	kr = mach_vm_page_range_query(map, start, size, prq_buf, &out_count);

	// yes, EFAULT as a kern_return_t because mach_vm_page_range_query returns copyio's error
	if (kr == EFAULT) {
		bool bad = false;
		for (unsigned i = 0; i < prq_buf_size / sizeof(uint32_t); i++) {
			if (((uint32_t *)prq_buf)[i] == 0xffffffff) {
				// kernel didn't fill the entire writeable buffer, that's bad
				bad = true;
				break;
			}
		}
		if (!bad) {
			// kernel filled our buffer and then hit our fault page
			// we'll allow it
			kr = 0;
		}
	}

	check_mach_vm_page_range_query_outparam_changes(&kr, out_count, in_count);
	(void)mach_vm_deallocate(map, prq_buf, prq_buf_size + KB16);

	return kr;
}

static int
call_mincore(void *start, size_t size)
{
	// mincore writes one byte per page output
	// and can accept any address range as input
	// We can't provide that much storage for very large lengths.
	// Instead we provide a limited output buffer,
	// write-protect the page after it, and "succeed" if the kernel
	// fills the buffer and then returns EFAULT.

	// enough space for MAX_PAGE_RANGE_QUERY with 4KB pages, twice
	size_t mincore_buf_size = 2 * 262144;
	char *mincore_buf = 0;
	mincore_buf = mmap(NULL, mincore_buf_size + KB16, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	assert(mincore_buf != MAP_FAILED);

	// protect the guard page
	char *mincore_guard = mincore_buf + mincore_buf_size;
	int err = mprotect(mincore_guard, KB16, PROT_NONE);
	assert(err == 0);

	// pre-fill the output buffer with an invalid value
	memset(mincore_buf, 0xff, mincore_buf_size);

	int ret;
	err = mincore(start, size, mincore_buf);
	if (err == 0) {
		ret = 0;
	} else if (errno != EFAULT) {
		ret = errno;
	} else {
		// EFAULT - check if kernel hit our guard page
		bool bad = false;
		for (unsigned i = 0; i < mincore_buf_size; i++) {
			if (mincore_buf[i] == (char)0xff) {
				// kernel didn't fill the entire writeable buffer, that's bad
				bad = true;
				break;
			}
		}
		if (!bad) {
			// kernel filled our buffer and then hit our guard page
			// we'll allow it
			ret = 0;
		} else {
			ret = errno;
		}
	}

	(void)munmap(mincore_buf, mincore_buf_size + PAGE_SIZE);

	return ret;
}

// TODO: re-enable deferred reclaim tests (rdar://136157720)
#if 0
typedef kern_return_t (*fn_mach_vm_deferred_reclamation_buffer_init)(task_t task, mach_vm_address_t address, mach_vm_size_t size);

static results_t *
test_mach_vm_deferred_reclamation_buffer_init(fn_mach_vm_deferred_reclamation_buffer_init func,
    const char * testname)
{
	int ret = 0;
	// Set vm.reclaim_max_threshold to non-zero
	int orig_reclaim_max_threshold = 0;
	int new_reclaim_max_threshold = 1;
	size_t size = sizeof(orig_reclaim_max_threshold);
	int sysctl_res = sysctlbyname("vm.reclaim_max_threshold", &orig_reclaim_max_threshold, &size, NULL, 0);
	assert(sysctl_res == 0);
	sysctl_res = sysctlbyname("vm.reclaim_max_threshold", NULL, 0, &new_reclaim_max_threshold, size);
	assert(sysctl_res == 0);

	reclamation_buffer_init_trials_t *trials SMART_RECLAMATION_BUFFER_INIT_TRIALS();
	results_t *results = alloc_results(testname, eSMART_RECLAMATION_BUFFER_INIT_TRIALS, trials->count);

	// reserve last trial to run without modified sysctl
	for (unsigned i = 0; i < trials->count - 1; i++) {
		reclamation_buffer_init_trial_t trial = trials->list[i];
		ret = func(trial.task, trial.address, trial.size);
		append_result(results, ret, trial.name);
	}

	// run with vm.reclaim_max_threshold = 0 and exercise KERN_NOT_SUPPORTED path
	new_reclaim_max_threshold = 0;
	reclamation_buffer_init_trial_t last_trial = trials->list[trials->count - 1];

	sysctl_res = sysctlbyname("vm.reclaim_max_threshold", NULL, 0, &new_reclaim_max_threshold, size);
	assert(sysctl_res == 0);

	ret = func(last_trial.task, last_trial.address, last_trial.size);
	if (__improbable(ret == KERN_INVALID_ARGUMENT)) {
		// Unlikely case when args are rejected before sysctl check.
		// When this happens during test run, return acceptable, but if this happens
		// during golden file generation, record the expected value.
		ret = generate_golden ? KERN_NOT_SUPPORTED : ACCEPTABLE;
	}
	append_result(results, ret, last_trial.name);

	// Revert vm.reclaim_max_threshold to how we found it
	sysctl_res = sysctlbyname("vm.reclaim_max_threshold", NULL, 0, &orig_reclaim_max_threshold, size);
	assert(sysctl_res == 0);

	return results;
}
#endif // 0

static vm_map_kernel_flags_trials_t *
generate_mmap_kernel_flags_trials()
{
	// mmap rejects both ANYWHERE and FIXED | OVERWRITE
	// so don't set any prefix flags.
	return generate_prefixed_vm_map_kernel_flags_trials(0, "");
}


#define SMART_MMAP_KERNEL_FLAGS_TRIALS()                                \
	__attribute__((cleanup(cleanup_vm_map_kernel_flags_trials)))    \
	= generate_mmap_kernel_flags_trials()

static results_t *
test_mmap_with_allocated_vm_map_kernel_flags_t(kern_return_t (*func)(MAP_T map, mach_vm_address_t src, mach_vm_size_t size, int flags), const char * testname)
{
	MAP_T map SMART_MAP;

	allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	vm_map_kernel_flags_trials_t * trials SMART_MMAP_KERNEL_FLAGS_TRIALS();
	results_t *results = alloc_results(testname, eSMART_MMAP_KERNEL_FLAGS_TRIALS, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		kern_return_t ret = func(map, base.addr, base.size, trials->list[i].flags);
		append_result(results, ret, trials->list[i].name);
	}
	return results;
}

// Test a Unix function.
// Run each trial with an allocated vm region and a vm_inherit_t
typedef int (*unix_with_inherit_fn)(void *start, size_t size, int inherit);

static results_t *
test_unix_with_allocated_vm_inherit_t(unix_with_inherit_fn fn, const char * testname)
{
	MAP_T map SMART_MAP;
	allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	vm_inherit_trials_t *trials SMART_VM_INHERIT_TRIALS();
	results_t *results = alloc_results(testname, eSMART_VM_INHERIT_TRIALS, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		vm_inherit_trial_t trial = trials->list[i];
		int ret = fn((void*)(uintptr_t)base.addr, (size_t)base.size, (int)trial.value);
		append_result(results, ret, trial.name);
	}
	return results;
}

// Test a Unix function.
// Run each trial with an allocated vm region and a vm_msync_t
typedef int (*unix_with_msync_fn)(void *start, size_t size, int msync_value);

static results_t *
test_unix_with_allocated_vm_msync_t(unix_with_msync_fn fn, const char * testname)
{
	MAP_T map SMART_MAP;
	allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	vm_msync_trials_t *trials SMART_VM_MSYNC_TRIALS();
	results_t *results = alloc_results(testname, eSMART_VM_MSYNC_TRIALS, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		vm_msync_trial_t trial = trials->list[i];
		int ret = fn((void*)(uintptr_t)base.addr, (size_t)base.size, (int)trial.value);
		append_result(results, ret, trial.name);
	}
	return results;
}

// Test a Unix function.
// Run each trial with an allocated vm region and an advise
typedef int (*unix_with_advise_fn)(void *start, size_t size, int advise);

static results_t *
test_unix_with_allocated_aligned_vm_advise_t(unix_with_advise_fn fn, mach_vm_size_t align_mask, const char * testname)
{
	MAP_T map SMART_MAP;
	allocation_t base SMART_ALLOCATE_ALIGNED_VM(map, TEST_ALLOC_SIZE, align_mask, VM_PROT_DEFAULT);
	vm_advise_trials_t *trials SMART_VM_ADVISE_TRIALS();
	results_t *results = alloc_results(testname, eSMART_VM_ADVISE_TRIALS, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		vm_advise_trial_t trial = trials->list[i];
		int ret = fn((void*)(uintptr_t)base.addr, (size_t)base.size, (int)trial.value);
		append_result(results, ret, trial.name);
	}
	return results;
}

// Rosetta userspace intercepts shared_region_map_and_slide_2_np calls and this Rosetta wrapper
// function doesn't have the necessary checks to support invalid input arguments. Skip these trials
// intead of crashing the test.
static bool
shared_region_map_and_slide_would_crash(shared_region_map_and_slide_2_trial_t *trial)
{
	uint32_t files_count = trial->files_count;
	struct shared_file_np *files = trial->files;
	uint32_t mappings_count = trial->mappings_count;
	struct shared_file_mapping_slide_np *mappings = trial->mappings;

	if (files_count == 0 || files_count == 1 || files_count > _SR_FILE_MAPPINGS_MAX_FILES) {
		return true;
	}
	if (mappings_count == 0 || mappings_count > SFM_MAX) {
		return true;
	}
	if (!files) {
		return true;
	}
	if (!mappings) {
		return true;
	}
	if (mappings_count != (((files_count - 1) * kNumSharedCacheMappings) + 1) &&
	    mappings_count != (files_count * kNumSharedCacheMappings)) {
		return true;
	}
	if (files_count >= kMaxSubcaches) {
		return true;
	}
	return false;
}

typedef int (*unix_shared_region_map_and_slide_2_np)(uint32_t files_coun, const struct shared_file_np *files, uint32_t mappings_count, const struct shared_file_mapping_slide_np *mappings);

static results_t *
test_unix_shared_region_map_and_slide_2_np(unix_shared_region_map_and_slide_2_np func, const char *testname)
{
	uint64_t dyld_fp = (uint64_t)get_dyld_fd();
	shared_region_map_and_slide_2_trials_t *trials SMART_SHARED_REGION_MAP_AND_SLIDE_2_TRIALS(dyld_fp);
	results_t *results = alloc_results(testname, eSMART_SHARED_REGION_MAP_AND_SLIDE_2_TRIALS, dyld_fp, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		int ret;
		shared_region_map_and_slide_2_trial_t trial = trials->list[i];
		if (isRosetta() && shared_region_map_and_slide_would_crash(&trial)) {
			ret = IGNORED;
		} else {
			ret = func(trial.files_count, trial.files, trial.mappings_count, trial.mappings);
		}
		append_result(results, ret, trial.name);
	}

	close_dyld_fd();
	return results;
}

static results_t *
test_dst_size_fileoff(kern_return_t (*func)(MAP_T map, mach_vm_address_t dst, mach_vm_size_t size, mach_vm_address_t fileoff), const char * testname)
{
	MAP_T map SMART_MAP;
	src_dst_size_trials_t * trials SMART_FILEOFF_DST_SIZE_TRIALS();
	results_t *results = alloc_results(testname, eSMART_FILEOFF_DST_SIZE_TRIALS, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		src_dst_size_trial_t trial = trials->list[i];
		unallocation_t dst_base SMART_UNALLOCATE_VM(map, TEST_ALLOC_SIZE);
		// src a.k.a. mmap fileoff doesn't slide
		trial = slide_trial_dst(trial, dst_base.addr);
		int ret = func(map, trial.dst, trial.size, trial.src);
		append_result(results, ret, trial.name);
	}
	return results;
}

// Try to allocate a destination for mmap(MAP_FIXED) to overwrite.
// On exit:
// *out_dst *out_size are the allocation, or 0
// *out_panic is true if the trial should stop and record PANIC
// (because the trial specifies an absolute address that is already occupied)
// *out_slide is true if the trial should slide by *out_dst
static __attribute__((overloadable)) void
allocate_for_mmap_fixed(MAP_T map, mach_vm_address_t trial_dst, mach_vm_size_t trial_size, bool trial_dst_is_absolute, bool trial_size_is_absolute, mach_vm_address_t *out_dst, mach_vm_size_t *out_size, bool *out_panic, bool *out_slide)
{
	*out_panic = false;
	*out_slide = false;

	if (trial_dst_is_absolute && trial_size_is_absolute) {
		// known dst addr, known size
		*out_dst = trial_dst;
		*out_size = trial_size;
		kern_return_t kr = mach_vm_allocate(map, out_dst, *out_size, VM_FLAGS_FIXED);
		if (kr == KERN_NO_SPACE) {
			// this space is in use, we can't allow mmap to try to overwrite it
			*out_panic = true;
			*out_dst = 0;
			*out_size = 0;
		} else if (kr != 0) {
			// some other error, assume mmap will also fail
			*out_dst = 0;
			*out_size = 0;
		}
		// no slide, trial and allocation are already at the same place
		*out_slide = false;
	} else {
		// other cases either fit in a small allocation or fail
		*out_dst = 0;
		*out_size = TEST_ALLOC_SIZE;
		kern_return_t kr = mach_vm_allocate(map, out_dst, *out_size, VM_FLAGS_ANYWHERE);
		if (kr != 0) {
			// allocation error, assume mmap will also fail
			*out_dst = 0;
			*out_size = 0;
		}
		*out_slide = true;
	}
}

static __attribute__((overloadable)) void
allocate_for_mmap_fixed(MAP_T map, start_size_trial_t trial, mach_vm_address_t *out_dst, mach_vm_size_t *out_size, bool *out_panic, bool *out_slide)
{
	allocate_for_mmap_fixed(map, trial.start, trial.size, trial.start_is_absolute, trial.size_is_absolute,
	    out_dst, out_size, out_panic, out_slide);
}
static __attribute__((overloadable)) void
allocate_for_mmap_fixed(MAP_T map, src_dst_size_trial_t trial, mach_vm_address_t *out_dst, mach_vm_size_t *out_size, bool *out_panic, bool *out_slide)
{
	allocate_for_mmap_fixed(map, trial.dst, trial.size, trial.dst_is_absolute, !trial.size_is_dst_relative,
	    out_dst, out_size, out_panic, out_slide);
}

// Like test_dst_size_fileoff, but specialized for mmap(MAP_FIXED).
// mmap(MAP_FIXED) is destructive, forcibly unmapping anything
// already at that address.
// We must ensure that each trial is either obviously invalid and caught
// by the sanitizers, or is valid and overwrites an allocation we control.
static results_t *
test_fixed_dst_size_fileoff(kern_return_t (*func)(MAP_T map, mach_vm_address_t dst, mach_vm_size_t size, mach_vm_address_t fileoff), const char * testname)
{
	MAP_T map SMART_MAP;
	src_dst_size_trials_t * trials SMART_FILEOFF_DST_SIZE_TRIALS();
	results_t *results = alloc_results(testname, eSMART_FILEOFF_DST_SIZE_TRIALS, trials->count);
	for (unsigned i = 0; i < trials->count; i++) {
		src_dst_size_trial_t trial = trials->list[i];
		// Try to create an allocation for mmap to overwrite.
		mach_vm_address_t dst_alloc;
		mach_vm_size_t dst_size;
		bool should_panic;
		bool should_slide_trial;
		allocate_for_mmap_fixed(map, trial, &dst_alloc, &dst_size, &should_panic, &should_slide_trial);
		if (should_panic) {
			append_result(results, PANIC, trial.name);
			continue;
		}
		if (should_slide_trial) {
			// src a.k.a. mmap fileoff doesn't slide
			trial = slide_trial_dst(trial, dst_alloc);
		}

		kern_return_t ret = func(map, trial.dst, trial.size, trial.src);

		if (dst_alloc != 0) {
			(void)mach_vm_deallocate(map, dst_alloc, dst_size);
		}
		append_result(results, ret, trial.name);
	}
	return results;
}

// Like test_mach_with_allocated_start_size, but specialized for mmap(MAP_FIXED).
// See test_fixed_dst_size_fileoff for more.
static results_t *
test_fixed_dst_size(kern_return_t (*func)(MAP_T map, mach_vm_address_t dst, mach_vm_size_t size), const char *testname)
{
	MAP_T map SMART_MAP;
	start_size_trials_t *trials SMART_START_SIZE_TRIALS(0);  // no base addr
	results_t *results = alloc_results(testname, eSMART_START_SIZE_TRIALS, 0, trials->count);
	for (unsigned i = 0; i < trials->count; i++) {
		start_size_trial_t trial = trials->list[i];
		// Try to create an allocation for mmap to overwrite.
		mach_vm_address_t dst_alloc;
		mach_vm_size_t dst_size;
		bool should_panic;
		bool should_slide_trial;
		allocate_for_mmap_fixed(map, trial, &dst_alloc, &dst_size, &should_panic, &should_slide_trial);
		if (should_panic) {
			append_result(results, PANIC, trial.name);
			continue;
		}
		if (should_slide_trial) {
			trial = slide_trial(trial, dst_alloc);
		}

		kern_return_t ret = func(map, trial.start, trial.size);

		if (dst_alloc != 0) {
			(void)mach_vm_deallocate(map, dst_alloc, dst_size);
		}
		append_result(results, ret, trial.name);
	}
	return results;
}

static results_t *
test_allocated_src_allocated_dst_size(kern_return_t (*func)(MAP_T map, mach_vm_address_t src, mach_vm_size_t size, mach_vm_address_t dst), const char * testname)
{
	/*
	 * Require src < dst. Some tests may get different error codes if src > dst.
	 *
	 * (No actual examples are known today, but see the comment in
	 * test_allocated_src_unallocated_dst_size for an example in that
	 * function. Here we are being conservatively careful.)
	 *
	 * TODO: test both src < dst and src > dst.
	 */
	MAP_T map SMART_MAP;
	allocation_t src_base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	allocation_t dst_base SMART_ALLOCATE_VM_AFTER(map, src_base.addr, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	assert(src_base.addr < dst_base.addr);
	src_dst_size_trials_t * trials SMART_SRC_DST_SIZE_TRIALS();
	results_t *results = alloc_results(testname, eSMART_SRC_DST_SIZE_TRIALS, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		src_dst_size_trial_t trial = trials->list[i];
		trial = slide_trial_src(trial, src_base.addr);
		trial = slide_trial_dst(trial, dst_base.addr);
		int ret = func(map, trial.src, trial.size, trial.dst);
		// func should be fixed-overwrite, nothing new to deallocate
		append_result(results, ret, trial.name);
	}
	return results;
}

static task_exc_guard_behavior_t saved_exc_guard_behavior;

static void
disable_exc_guard()
{
	T_SETUPBEGIN;

	// Disable EXC_GUARD for the duration of the test.
	// We restore it at the end.
	kern_return_t kr = task_get_exc_guard_behavior(mach_task_self(), &saved_exc_guard_behavior);
	assert(kr == 0);

	kr = task_set_exc_guard_behavior(mach_task_self(), TASK_EXC_GUARD_NONE);
	if (kr) {
		T_LOG("warning, couldn't disable EXC_GUARD; some tests are disabled");
		EXC_GUARD_ENABLED = true;
	} else {
		EXC_GUARD_ENABLED = false;
	}

	T_SETUPEND;
}

static void
restore_exc_guard()
{
	// restore process's EXC_GUARD handling
	(void)task_set_exc_guard_behavior(mach_task_self(), saved_exc_guard_behavior);
}

static int
set_disable_vm_sanitize_telemetry_via_sysctl(uint32_t val)
{
	int ret = sysctlbyname("debug.disable_vm_sanitize_telemetry", NULL, NULL, &val, sizeof(uint32_t));
	if (ret != 0) {
		printf("sysctl failed with errno %d.\n", errno);
	}
	return ret;
}

static int
disable_vm_sanitize_telemetry(void)
{
	return set_disable_vm_sanitize_telemetry_via_sysctl(1);
}

static int
reenable_vm_sanitize_telemetry(void)
{
	return set_disable_vm_sanitize_telemetry_via_sysctl(0);
}

#define MAX_LINE_LENGTH 100
#define MAX_NUM_TESTS 350
#define TMP_DIR "/tmp/"
#define ASSETS_DIR "../assets/vm_parameter_validation/"
#define DECOMPRESS ASSETS_DIR "decompress.sh"
#define GOLDEN_FILE TMP_DIR "user_golden_image.log"

#define KERN_GOLDEN_FILE TMP_DIR "kern_golden_image.log"

results_t *golden_list[MAX_NUM_TESTS];
results_t *kern_list[MAX_NUM_TESTS];

#define FILL_TRIALS_NAMES_AND_CONTINUE(results, trials, t_count) { \
	for (unsigned i = 0; i < t_count; i++) { \
	/* trials names are free'd in dealloc_results() */ \
	        (results)->list[i].name = kstrdup((trials)->list[i].name); \
	} \
}

#define FILL_TRIALS_NAMES(results, trials) { \
	unsigned t_count = ((trials)->count < (results)->count) ? (trials)->count : (results)->count; \
	if ((trials)->count != (results)->count) { \
	        T_LOG("%s:%d Trials count mismatch, expected %u, golden file %u\n", \
	                __func__, __LINE__, (trials)->count, (results)->count); \
	}\
	FILL_TRIALS_NAMES_AND_CONTINUE((results), (trials), (t_count)) \
	break; \
}

static void
fill_golden_trials(uint64_t trialsargs[static TRIALSARGUMENTS_SIZE],
    results_t *results)
{
	trialsformula_t formula = results->trialsformula;
	uint64_t trialsargs0 = trialsargs[0];
	uint64_t trialsargs1 = trialsargs[1];
	switch (formula) {
	case eUNKNOWN_TRIALS:
		// Leave them empty
		T_FAIL("Golden file with unknown trials, testname: %s\n", results->testname);
		break;
	case eSMART_VM_MAP_KERNEL_FLAGS_TRIALS: {
		vm_map_kernel_flags_trials_t * trials SMART_VM_MAP_KERNEL_FLAGS_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_VM_INHERIT_TRIALS: {
		vm_inherit_trials_t *trials SMART_VM_INHERIT_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_MMAP_KERNEL_FLAGS_TRIALS: {
		vm_map_kernel_flags_trials_t * trials SMART_MMAP_KERNEL_FLAGS_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_MMAP_FLAGS_TRIALS: {
		mmap_flags_trials_t *trials SMART_MMAP_FLAGS_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_GENERIC_FLAG_TRIALS: {
		generic_flag_trials_t *trials SMART_GENERIC_FLAG_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_VM_TAG_TRIALS: {
		// special case, trails (vm_tag_trials_values) depend on data only available on KERNEL
		vm_tag_trials_t *trials SMART_VM_TAG_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_VM_PROT_TRIALS: {
		vm_prot_trials_t *trials SMART_VM_PROT_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_VM_PROT_PAIR_TRIALS: {
		vm_prot_pair_trials_t *trials SMART_VM_PROT_PAIR_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_LEDGER_TAG_TRIALS: {
		ledger_tag_trials_t *trials SMART_LEDGER_TAG_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_LEDGER_FLAG_TRIALS: {
		ledger_flag_trials_t *trials SMART_LEDGER_FLAG_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_ADDR_TRIALS: {
		addr_trials_t *trials SMART_ADDR_TRIALS(trialsargs0);
		if (trialsargs1) {
			// Special case with an additional trial such that obj_size + addr == 0
			FILL_TRIALS_NAMES_AND_CONTINUE(results, trials, trials->count);
			assert(trials->count + 1 == results->count);
			char *trial_desc;
			kasprintf(&trial_desc, "addr: -0x%llx", trialsargs1);
			results->list[results->count - 1].name = kstrdup(trial_desc);
			kfree_str(trial_desc);
			break;
		} else {
			FILL_TRIALS_NAMES(results, trials);
		}
	}
	case eSMART_SIZE_TRIALS: {
		size_trials_t *trials SMART_SIZE_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_START_SIZE_TRIALS: {
		// NB: base.addr is not constant between runs but doesn't affect trial name
		start_size_trials_t *trials SMART_START_SIZE_TRIALS(trialsargs0);
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_START_SIZE_OFFSET_OBJECT_TRIALS: {
		start_size_offset_object_trials_t *trials SMART_START_SIZE_OFFSET_OBJECT_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_START_SIZE_OFFSET_TRIALS: {
		start_size_offset_trials_t *trials SMART_START_SIZE_OFFSET_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_SIZE_SIZE_TRIALS: {
		T_FAIL("SIZE_SIZE_TRIALS not used\n");
		break;
	}
	case eSMART_SRC_DST_SIZE_TRIALS: {
		src_dst_size_trials_t * trials SMART_SRC_DST_SIZE_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_FILEOFF_DST_SIZE_TRIALS: {
		src_dst_size_trials_t * trials SMART_FILEOFF_DST_SIZE_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_VM_BEHAVIOR_TRIALS: {
		vm_behavior_trials_t *trials SMART_VM_BEHAVIOR_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_VM_ADVISE_TRIALS: {
		vm_advise_trials_t *trials SMART_VM_ADVISE_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_VM_SYNC_TRIALS: {
		vm_sync_trials_t *trials SMART_VM_SYNC_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_VM_MSYNC_TRIALS: {
		vm_msync_trials_t *trials SMART_VM_MSYNC_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_VM_MACHINE_ATTRIBUTE_TRIALS: {
		vm_machine_attribute_trials_t *trials SMART_VM_MACHINE_ATTRIBUTE_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_VM_PURGEABLE_AND_STATE_TRIALS: {
		vm_purgeable_and_state_trials_t *trials SMART_VM_PURGEABLE_AND_STATE_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_START_SIZE_START_SIZE_TRIALS: {
		start_size_start_size_trials_t *trials SMART_START_SIZE_START_SIZE_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_SHARED_REGION_MAP_AND_SLIDE_2_TRIALS: {
		shared_region_map_and_slide_2_trials_t *trials SMART_SHARED_REGION_MAP_AND_SLIDE_2_TRIALS(trialsargs0);
		FILL_TRIALS_NAMES(results, trials);
	}
	case eSMART_RECLAMATION_BUFFER_INIT_TRIALS: {
#if 0
		reclamation_buffer_init_trials_t * trials SMART_RECLAMATION_BUFFER_INIT_TRIALS();
		FILL_TRIALS_NAMES(results, trials);
#else
		break;
#endif
	}
	default:
		T_FAIL("New formula %u, args %llu %llu, update fill_golden_trials, testname: %s\n",
		    formula, trialsargs[0], trialsargs[1], results->testname);
	}
}

// Number of test trials with ret == OUT_PARAM_BAD
int out_param_bad_count = 0;

static results_t *
test_name_to_golden_results(const char* testname)
{
	results_t *golden_results = NULL;
	results_t *golden_results_found = NULL;

	for (uint32_t x = 0; x < num_tests; x++) {
		golden_results = golden_list[x];
		if (strncmp(golden_results->testname, testname, strlen(testname)) == 0) {
			golden_results->tested_count += 1;
			golden_results_found = golden_results;
			break;
		}
	}

	return golden_results_found;
}

static void
dump_results_list(results_t *res_list[], uint32_t res_num_tests)
{
	for (uint32_t x = 0; x < res_num_tests; x++) {
		results_t *results = res_list[x];
		testprintf("\t[%u] %s (%u)\n", x, results->testname, results->count);
	}
}

static void
dump_golden_list()
{
	testprintf("======\n");
	testprintf("golden_list %p, num_tests %u\n", golden_list, num_tests);
	dump_results_list(golden_list, num_tests);
	testprintf("======\n");
}

static void
dump_kernel_results_list()
{
	testprintf("======\n");
	testprintf("kernel_results_list %p, num_tests %u\n", kern_list, num_kern_tests);
	dump_results_list(kern_list, num_kern_tests);
	testprintf("======\n");
}

// Read results written by dump_golden_results().
static int
populate_golden_results(const char *filename)
{
	FILE *file;
	char line[MAX_LINE_LENGTH];
	char trial_formula[20];
	results_t *results = NULL;
	trialsformula_t formula = eUNKNOWN_TRIALS;
	uint64_t trial_args[TRIALSARGUMENTS_SIZE] = {0, 0};
	uint32_t num_results = 0;
	uint32_t result_number = 0;
	int result_ret = 0;
	char *test_name = NULL;
	char *sub_line = NULL;
	char *s_num_results = NULL;
	bool in_test = FALSE;
	out_param_bad_count = 0;
	kern_trialname_generation = strnstr(filename, "kern_golden_image", strlen(filename)) != NULL;

	// cd to the directory containing this executable
	// Test files are located relative to there.
	uint32_t exesize = 0;
	_NSGetExecutablePath(NULL, &exesize);
	char *exe = malloc(exesize);
	assert(exe != NULL);
	_NSGetExecutablePath(exe, &exesize);
	char *dir = dirname(exe);
	chdir(dir);
	free(exe);

	file = fopen(filename, "r");
	if (file == NULL) {
		T_FAIL("Could not open file %s\n", filename);
		return 1;
	}

	// Read file line by line
	while (fgets(line, MAX_LINE_LENGTH, file) != NULL) {
		// Check if the line starts with "TESTNAME" or "RESULT COUNT"
		if (strncmp(line, TESTNAME_DELIMITER, strlen(TESTNAME_DELIMITER)) == 0) {
			// remove the newline char
			line[strcspn(line, "\n")] = 0;
			sub_line = line + strlen(TESTNAME_DELIMITER);
			test_name = strdup(sub_line);
			formula = eUNKNOWN_TRIALS;
			trial_args[0] = TRIALSARGUMENTS_NONE;
			trial_args[1] = TRIALSARGUMENTS_NONE;
			// T_LOG("TESTNAME %u : %s", num_tests, test_name);
			in_test = TRUE;
		} else if (in_test && strncmp(line, TRIALSFORMULA_DELIMITER, strlen(TRIALSFORMULA_DELIMITER)) == 0) {
			sscanf(line, "%*s %s %*s %llu,%llu,%llu", trial_formula, &trial_args[0], &trial_args[1], &trial_page_size);
			formula = trialsformula_from_string(trial_formula);
		} else if (in_test && strncmp(line, RESULTCOUNT_DELIMITER, strlen(RESULTCOUNT_DELIMITER)) == 0) {
			assert(num_tests < MAX_NUM_TESTS);
			s_num_results = line + strlen(RESULTCOUNT_DELIMITER);
			num_results = (uint32_t)strtoul(s_num_results, NULL, 10);
			results = alloc_results(test_name, formula, trial_args, TRIALSARGUMENTS_SIZE, num_results);
			assert(results);
			results->count = num_results;
			fill_golden_trials(trial_args, results);
			golden_list[num_tests++] = results;
			// T_LOG("num_tests %u, testname %s, count: %u", num_tests, results->testname, results->count);
		} else if (in_test && strncmp(line, TESTRESULT_DELIMITER, strlen(TESTRESULT_DELIMITER)) == 0) {
			sscanf(line, "%d: %d", &result_number, &result_ret);
			assert(result_number < num_results);
			// T_LOG("\tresult #%u: %d\n", result_number, result_ret);
			results->list[result_number].ret = result_ret;
			if (result_ret == OUT_PARAM_BAD) {
				out_param_bad_count += 1;
				T_FAIL("Out parameter violation in test %s - %s\n", results->testname, results->list[result_number].name);
			}
		} else {
			// T_LOG("Unknown line: %s\n", line);
			in_test = FALSE;
		}
	}

	fclose(file);

	if (!out_param_bad_count) {
		dump_golden_list();
	}
	kern_trialname_generation = FALSE;

	return out_param_bad_count;
}

static void
clean_golden_results()
{
	for (uint32_t x = 0; x < num_tests; ++x) {
		if (golden_list[x]->tested_count == 0) {
			T_LOG("WARN: Test %s found in golden file but no test with that name was run\n",
			    golden_list[x]->testname);
		}
		if (golden_list[x]->tested_count > 1) {
			T_LOG("WARN: Test %s found in golden file with %d runs\n",
			    golden_list[x]->testname, golden_list[x]->tested_count);
		}
		dealloc_results(golden_list[x]);
		golden_list[x] = NULL;
	}
}

static void
clean_kernel_results()
{
	for (uint32_t x = 0; x < num_kern_tests; ++x) {
		dealloc_results(kern_list[x]);
		kern_list[x] = NULL;
	}
}

// buffer to output userspace golden file results (using same size as the kern buffer)
static const int64_t GOLDEN_OUTPUT_BUFFER_SIZE = SYSCTL_OUTPUT_BUFFER_SIZE;
static char* GOLDEN_OUTPUT_START;
static char* GOLDEN_OUTPUT_BUF;
static char* GOLDEN_OUTPUT_END;

void
goldenprintf(const char *format, ...)
{
	if (!GOLDEN_OUTPUT_START) {
		GOLDEN_OUTPUT_START = calloc(GOLDEN_OUTPUT_BUFFER_SIZE, 1);
		GOLDEN_OUTPUT_BUF = GOLDEN_OUTPUT_START;
		GOLDEN_OUTPUT_END = GOLDEN_OUTPUT_BUF + GOLDEN_OUTPUT_BUFFER_SIZE;
	}

	int printed;
	ssize_t s_buffer_size = GOLDEN_OUTPUT_END - GOLDEN_OUTPUT_BUF;
	assert(s_buffer_size > 0 && s_buffer_size <= GOLDEN_OUTPUT_BUFFER_SIZE);
	size_t buffer_size = (size_t)s_buffer_size;
	va_list args;
	va_start(args, format);
	printed = vsnprintf(GOLDEN_OUTPUT_BUF, buffer_size, format, args);
	va_end(args);
	assert(printed >= 0);
	assert((unsigned)printed < buffer_size - 1);
	assert(GOLDEN_OUTPUT_BUF + printed + 1 < GOLDEN_OUTPUT_END);
	GOLDEN_OUTPUT_BUF += printed;
}

// Verbose output in dump_results, controlled by DUMP_RESULTS env.
bool dump = FALSE;
// Output to create a golden test result, controlled by GENERATE_GOLDEN_IMAGE.
bool generate_golden = FALSE;
// Read existing golden file and print its contents in verbose format (like dump_results). Controlled by DUMP_GOLDEN_IMAGE.
bool dump_golden = FALSE;
// Run tests as tests (i.e. emit TS_{PASS/FAIL}), enabled unless golden image generation is true.
bool should_test_results =  TRUE;

T_DECL(vm_parameter_validation_user,
    "parameter validation for userspace calls",
    T_META_SPAWN_TOOL(DECOMPRESS),
    T_META_SPAWN_TOOL_ARG("user"),
    T_META_SPAWN_TOOL_ARG(TMP_DIR),
    T_META_SPAWN_TOOL_ARG(GOLDEN_FILES_VERSION)
    )
{
	if (disable_vm_sanitize_telemetry() != 0) {
		T_FAIL("Could not disable VM API telemetry. Bailing out early.");
		return;
	}

	read_env();

	T_LOG("dump %d, golden %d, dump_golden %d, test %d\n", dump, generate_golden, dump_golden, should_test_results);

	if (generate_golden && unsigned_code_is_disallowed()) {
		// Some test results change when SIP is enabled.
		// Golden files must record the SIP-disabled values.
		T_FAIL("Can't generate golden files with SIP enabled. Disable SIP and try again.\n");
		return;
	}

	if ((dump_golden || should_test_results) && populate_golden_results(GOLDEN_FILE)) {
		// bail out early, problem loading golden test results
		T_FAIL("Could not load golden file '%s'\n", GOLDEN_FILE);
		return;
	}

	set_up_guard_page();

	disable_exc_guard();

	if (dump_golden) {
		// just print the parsed golden file
		for (uint32_t x = 0; x < num_tests; ++x) {
			__dump_results(golden_list[x]);
		}
		goto out;
	}

	/*
	 * -- memory entry functions --
	 * The memory entry test functions use macros to generate each flavor of memory entry function.
	 * This is partially becauseof many entrypoints (mach_make_memory_entry/mach_make_memory_entry_64/mach_make_memory_entry)
	 * and partially because many flavors of each function are called (copy/memonly/share/...).
	 */

	// Mach start/size with both old-style and new-style types
	// (co-located so old and new can be compared more easily)
#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_start_size(fn, name " (start/size)")))
#define RUN_OLD64(fn, name) RUN_NEW(fn, name)
#else
#define RUN_OLD(fn, name) do {} while (0)
#define RUN_OLD64(fn, name) do {} while (0)
#endif
	// mach_make_memory_entry has up to three entry points on U32, unlike other functions that have two
	RUN_NEW(call_mach_make_memory_entry_64__start_size__copy, "mach_make_memory_entry_64 (copy)");
	RUN_OLD(call_mach_make_memory_entry__start_size__copy, "mach_make_memory_entry (copy)");
	RUN_OLD64(call__mach_make_memory_entry__start_size__copy, "_mach_make_memory_entry (copy)");
	RUN_NEW(call_mach_make_memory_entry_64__start_size__memonly, "mach_make_memory_entry_64 (mem_only)");
	RUN_OLD(call_mach_make_memory_entry__start_size__memonly, "mach_make_memory_entry (mem_only)");
	RUN_OLD64(call__mach_make_memory_entry__start_size__memonly, "_mach_make_memory_entry (mem_only)");
	RUN_NEW(call_mach_make_memory_entry_64__start_size__namedcreate, "mach_make_memory_entry_64 (named_create)");
	RUN_OLD(call_mach_make_memory_entry__start_size__namedcreate, "mach_make_memory_entry (named_create)");
	RUN_OLD64(call__mach_make_memory_entry__start_size__namedcreate, "_mach_make_memory_entry (named_create)");
	RUN_NEW(call_mach_make_memory_entry_64__start_size__share, "mach_make_memory_entry_64 (share)");
	RUN_OLD(call_mach_make_memory_entry__start_size__share, "mach_make_memory_entry (share)");
	RUN_OLD64(call__mach_make_memory_entry__start_size__share, "_mach_make_memory_entry (share)");
	RUN_NEW(call_mach_make_memory_entry_64__start_size__namedreuse, "mach_make_memory_entry_64 (named_reuse)");
	RUN_OLD(call_mach_make_memory_entry__start_size__namedreuse, "mach_make_memory_entry (named_reuse)");
	RUN_OLD64(call__mach_make_memory_entry__start_size__namedreuse, "_mach_make_memory_entry (named_reuse)");
#undef RUN_NEW
#undef RUN_OLD
#undef RUN_OLD64

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_size(fn, name " (size)")))
	RUN(call_mach_memory_object_memory_entry_64__size, "mach_memory_object_memory_entry_64");
	RUN(call_replacement_mach_memory_object_memory_entry__size, "mach_memory_object_memory_entry");
#undef RUN

#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
#define RUN_OLD64(fn, name) RUN_NEW(fn, name)

	RUN_NEW(call_mach_make_memory_entry_64__vm_prot, "mach_make_memory_entry_64");
#if TEST_OLD_STYLE_MACH
	RUN_OLD(call_mach_make_memory_entry__vm_prot, "mach_make_memory_entry");
	RUN_OLD64(call__mach_make_memory_entry__vm_prot, "_mach_make_memory_entry");
#endif

#undef RUN_NEW
#undef RUN_OLD
#undef RUN_OLD64

#define RUN(fn, name) dealloc_results(process_results(test_mach_vm_prot(fn, name " (vm_prot_t)")))
	RUN(call_mach_memory_object_memory_entry_64__vm_prot, "mach_memory_object_memory_entry_64");
	RUN(call_replacement_mach_memory_object_memory_entry__vm_prot, "mach_memory_object_memory_entry");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_ledger_tag(fn, name " (ledger tag)")))
	RUN(call_mach_memory_entry_ownership__ledger_tag, "mach_memory_entry_ownership");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_ledger_flag(fn, name " (ledger flag)")))
	RUN(call_mach_memory_entry_ownership__ledger_flag, "mach_memory_entry_ownership");
#undef RUN

	/*
	 * -- allocate/deallocate functions --
	 */

#define RUN(fn, name) dealloc_results(process_results(test_mach_allocation_func_with_start_size(fn, name)))
	RUN(call_mach_vm_allocate__start_size_fixed, "mach_vm_allocate (fixed) (realigned start/size)");
	RUN(call_mach_vm_allocate__start_size_anywhere, "mach_vm_allocate (anywhere) (hint/size)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_allocation_func_with_vm_map_kernel_flags_t(fn, name " (vm_map_kernel_flags_t)")))
	RUN(call_mach_vm_allocate__flags, "mach_vm_allocate");
#undef RUN

	dealloc_results(process_results(test_deallocator(call_mach_vm_deallocate, "mach_vm_deallocate (start/size)")));
#if TEST_OLD_STYLE_MACH
	dealloc_results(process_results(test_deallocator(call_vm_deallocate, "vm_deallocate (start/size)")));
#endif

#define RUN(fn, name) dealloc_results(process_results(test_deallocator(fn, name " (start/size)")))
	RUN(call_munmap, "munmap");
#undef RUN

	/*
	 * -- map/unmap functions --
	 * The map/unmap functions use multiple layers of macros.
	 * The macros are used both for function generation (see IMPL_ONE_FROM_HELPER) and to call all of those.
	 * This was written this way to further avoid lots of code duplication, as the map/remap functions
	 * have many different parameter combinations we want to test.
	 */

	// map tests

#define RUN_START_SIZE(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (realigned start/size)")))
#define RUN_HINT_SIZE(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (hint/size)")))
#define RUN_PROT_PAIR(fn, name) dealloc_results(process_results(test_mach_vm_prot_pair(fn, name " (prot_pairs)")))
#define RUN_INHERIT(fn, name) dealloc_results(process_results(test_mach_with_allocated_vm_inherit_t(fn, name " (vm_inherit_t)")))
#define RUN_FLAGS(fn, name) dealloc_results(process_results(test_mach_allocation_func_with_vm_map_kernel_flags_t(fn, name " (vm_map_kernel_flags_t)")))
#define RUN_SSOO(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size_offset_object(fn, name " (start/size/offset/object)")))

#define RUN_ALL(fn, name)     \
	RUN_START_SIZE(call_ ## fn ## __allocate_fixed, #name " (allocate fixed overwrite)");   \
	RUN_START_SIZE(call_ ## fn ## __allocate_fixed_copy, #name " (allocate fixed overwrite copy)");  \
	RUN_START_SIZE(call_ ## fn ## __memobject_fixed, #name " (memobject fixed overwrite)");  \
	RUN_START_SIZE(call_ ## fn ## __memobject_fixed_copy, #name " (memobject fixed overwrite copy)"); \
	RUN_HINT_SIZE(call_ ## fn ## __allocate_anywhere, #name " (allocate anywhere)");  \
	RUN_HINT_SIZE(call_ ## fn ## __memobject_anywhere, #name " (memobject anywhere)");  \
	RUN_PROT_PAIR(call_ ## fn ## __allocate_fixed__prot_pairs, #name " (allocate fixed overwrite)");  \
	RUN_PROT_PAIR(call_ ## fn ## __allocate_fixed_copy__prot_pairs, #name " (allocate fixed overwrite copy)");  \
	RUN_PROT_PAIR(call_ ## fn ## __allocate_anywhere__prot_pairs, #name " (allocate anywhere)");  \
	RUN_PROT_PAIR(call_ ## fn ## __memobject_fixed__prot_pairs, #name " (memobject fixed overwrite)");  \
	RUN_PROT_PAIR(call_ ## fn ## __memobject_fixed_copy__prot_pairs, #name " (memobject fixed overwrite copy)");  \
	RUN_PROT_PAIR(call_ ## fn ## __memobject_anywhere__prot_pairs, #name " (memobject anywhere)");  \
	RUN_INHERIT(call_ ## fn ## __allocate_fixed__inherit, #name " (allocate fixed overwrite)");  \
	RUN_INHERIT(call_ ## fn ## __allocate_fixed_copy__inherit, #name " (allocate fixed overwrite copy)");  \
	RUN_INHERIT(call_ ## fn ## __allocate_anywhere__inherit, #name " (allocate anywhere)");  \
	RUN_INHERIT(call_ ## fn ## __memobject_fixed__inherit, #name " (memobject fixed overwrite)");  \
	RUN_INHERIT(call_ ## fn ## __memobject_fixed_copy__inherit, #name " (memobject fixed overwrite copy)");  \
	RUN_INHERIT(call_ ## fn ## __memobject_anywhere__inherit, #name " (memobject anywhere)");  \
	RUN_FLAGS(call_ ## fn ## __allocate__flags, #name " (allocate)");  \
	RUN_FLAGS(call_ ## fn ## __allocate_copy__flags, #name " (allocate copy)");  \
	RUN_FLAGS(call_ ## fn ## __memobject__flags, #name " (memobject)");  \
	RUN_FLAGS(call_ ## fn ## __memobject_copy__flags, #name " (memobject copy)");  \
	RUN_SSOO(call_ ## fn ## __memobject_fixed__start_size_offset_object, #name " (memobject fixed overwrite)");  \
	RUN_SSOO(call_ ## fn ## __memobject_fixed_copy__start_size_offset_object, #name " (memobject fixed overwrite copy)");  \
	RUN_SSOO(call_ ## fn ## __memobject_anywhere__start_size_offset_object, #name " (memobject anywhere)");  \

	RUN_ALL(mach_vm_map_wrapped, mach_vm_map);
#if TEST_OLD_STYLE_MACH
	RUN_ALL(vm_map_64_retyped, vm_map_64);
	RUN_ALL(vm_map_retyped, vm_map);
#endif

#undef RUN_ALL
#undef RUN_START_SIZE
#undef RUN_HINT_SIZE
#undef RUN_PROT_PAIR
#undef RUN_INHERIT
#undef RUN_FLAGS
#undef RUN_SSOO

	// remap tests

#define FN_NAME(fn, variant, type) call_ ## fn ## __  ## variant ## __ ## type
#define RUN_HELPER(harness, fn, variant, type, type_name, name) dealloc_results(process_results(harness(FN_NAME(fn, variant, type), #name " (" #variant ") (" type_name ")")))
#define RUN_SRC_SIZE(fn, variant, type_name, name) RUN_HELPER(test_mach_with_allocated_start_size, fn, variant, src_size, type_name, name)
#define RUN_DST_SIZE(fn, variant, type_name, name) RUN_HELPER(test_mach_with_allocated_start_size, fn, variant, dst_size, type_name, name)
#define RUN_PROT_PAIRS(fn, variant, name) RUN_HELPER(test_mach_with_allocated_vm_prot_pair, fn, variant, prot_pairs, "prot_pairs", name)
#define RUN_INHERIT(fn, variant, name) RUN_HELPER(test_mach_with_allocated_vm_inherit_t, fn, variant, inherit, "inherit", name)
#define RUN_FLAGS(fn, variant, name) RUN_HELPER(test_mach_with_allocated_vm_map_kernel_flags_t, fn, variant, flags, "flags", name)
#define RUN_SRC_DST_SIZE(fn, dst, variant, type_name, name) RUN_HELPER(test_allocated_src_##dst##_dst_size, fn, variant, src_dst_size, type_name, name)

#define RUN_ALL(fn, realigned, name)                                    \
	RUN_SRC_SIZE(fn, copy, realigned "src/size", name);             \
	RUN_SRC_SIZE(fn, nocopy, realigned "src/size", name);           \
	RUN_DST_SIZE(fn, fixed, "realigned dst/size", name);            \
	RUN_DST_SIZE(fn, fixed_copy, "realigned dst/size", name);       \
	RUN_DST_SIZE(fn, anywhere, "hint/size", name);                  \
	RUN_INHERIT(fn, fixed, name);                                   \
	RUN_INHERIT(fn, fixed_copy, name);                              \
	RUN_INHERIT(fn, anywhere, name);                                \
	RUN_FLAGS(fn, nocopy, name);                                    \
	RUN_FLAGS(fn, copy, name);                                      \
	RUN_PROT_PAIRS(fn, fixed, name);                                \
	RUN_PROT_PAIRS(fn, fixed_copy, name);                           \
	RUN_PROT_PAIRS(fn, anywhere, name);                             \
	RUN_SRC_DST_SIZE(fn, allocated, fixed, "src/dst/size", name);   \
	RUN_SRC_DST_SIZE(fn, allocated, fixed_copy, "src/dst/size", name); \
	RUN_SRC_DST_SIZE(fn, unallocated, anywhere, "src/dst/size", name); \

	RUN_ALL(mach_vm_remap_user, "realigned ", mach_vm_remap);
	RUN_ALL(mach_vm_remap_new_user, , mach_vm_remap_new);

#if TEST_OLD_STYLE_MACH
	RUN_ALL(vm_remap_retyped, "realigned ", vm_remap);
#endif

#undef RUN_ALL
#undef RUN_HELPER
#undef RUN_SRC_SIZE
#undef RUN_DST_SIZE
#undef RUN_PROT_PAIRS
#undef RUN_INHERIT
#undef RUN_FLAGS
#undef RUN_SRC_DST_SIZE

	// mmap tests

#define RUN(fn, name) dealloc_results(process_results(test_mmap_with_allocated_vm_map_kernel_flags_t(fn, name " (kernel flags)")))
	RUN(call_mmap__anon_private__kernel_flags, "mmap (anon private)");
	RUN(call_mmap__anon_shared__kernel_flags, "mmap (anon shared)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_mmap_flags(fn, name " (mmap flags)")))
	RUN(call_mmap__mmap_flags, "mmap");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (hint/size)")))
	RUN(call_mmap__file_private__start_size, "mmap (file private)");
	RUN(call_mmap__anon_private__start_size, "mmap (anon private)");
	RUN(call_mmap__file_shared__start_size, "mmap (file shared)");
	RUN(call_mmap__anon_shared__start_size, "mmap (anon shared)");
	RUN(call_mmap__file_private_codesign__start_size, "mmap (file private codesign)");
	RUN(call_mmap__file_private_media__start_size, "mmap (file private media)");
	RUN(call_mmap__nounix03_private__start_size, "mmap (no unix03)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_fixed_dst_size(fn, name " (dst/size)")))
	RUN(call_mmap__fixed_private__start_size, "mmap (fixed)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (offset/size)")))
	RUN(call_mmap__file_private__offset_size, "mmap (file private)");
	RUN(call_mmap__anon_private__offset_size, "mmap (anon private)");
	RUN(call_mmap__file_shared__offset_size, "mmap (file shared)");
	RUN(call_mmap__anon_shared__offset_size, "mmap (anon shared)");
	RUN(call_mmap__file_private_codesign__offset_size, "mmap (file private codesign)");
	RUN(call_mmap__file_private_media__offset_size, "mmap (file private media)");
	RUN(call_mmap__nounix03_private__offset_size, "mmap (no unix03)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_dst_size_fileoff(fn, name " (hint/size/fileoff)")))
	RUN(call_mmap__file_private__dst_size_fileoff, "mmap (file private)");
	RUN(call_mmap__anon_private__dst_size_fileoff, "mmap (anon private)");
	RUN(call_mmap__file_shared__dst_size_fileoff, "mmap (file shared)");
	RUN(call_mmap__anon_shared__dst_size_fileoff, "mmap (anon shared)");
	RUN(call_mmap__file_private_codesign__dst_size_fileoff, "mmap (file private codesign)");
	RUN(call_mmap__file_private_media__dst_size_fileoff, "mmap (file private media)");
	RUN(call_mmap__nounix03_private__dst_size_fileoff, "mmap (no unix03)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_fixed_dst_size_fileoff(fn, name " (dst/size/fileoff)")))
	RUN(call_mmap__fixed_private__dst_size_fileoff, "mmap (fixed)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
	RUN(call_mmap__file_private__vm_prot, "mmap (file private)");
	RUN(call_mmap__anon_private__vm_prot, "mmap (anon private)");
	RUN(call_mmap__file_shared__vm_prot, "mmap (file shared)");
	RUN(call_mmap__anon_shared__vm_prot, "mmap (anon shared)");
	RUN(call_mmap__file_private_codesign__vm_prot, "mmap (file private codesign)");
	RUN(call_mmap__file_private_media__vm_prot, "mmap (file private media)");
	RUN(call_mmap__nounix03_private__vm_prot, "mmap (no unix03)");
	RUN(call_mmap__fixed_private__vm_prot, "mmap (fixed)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_unix_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_mremap_encrypted, "mremap_encrypted");
#undef RUN

	/*
	 * -- wire/unwire functions --
	 */

#define RUN(fn, name) dealloc_results(process_results(test_unix_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_mlock, "mlock");
	RUN(call_munlock, "munlock");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_mach_vm_wire__wire, "mach_vm_wire (wire)");
	RUN(call_replacement_vm_wire__wire, "vm_wire (wire)");
	RUN(call_mach_vm_wire__unwire, "mach_vm_wire (unwire)");
	RUN(call_replacement_vm_wire__unwire, "vm_wire (unwire)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
	RUN(call_mach_vm_wire__vm_prot, "mach_vm_wire");
	RUN(call_replacement_vm_wire__vm_prot, "vm_wire");
#undef RUN

	/*
	 * -- copyin/copyout functions --
	 */

#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_start_size(fn, name " (start/size)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_read, "mach_vm_read");
	RUN_OLD(call_vm_read, "vm_read");
	RUN_NEW(call_mach_vm_read_list, "mach_vm_read_list");
	RUN_OLD(call_vm_read_list, "vm_read_list");

	RUN_NEW(call_mach_vm_read_overwrite__src, "mach_vm_read_overwrite (src)");
	RUN_NEW(call_mach_vm_read_overwrite__dst, "mach_vm_read_overwrite (dst)");
	RUN_OLD(call_vm_read_overwrite__src, "vm_read_overwrite (src)");
	RUN_OLD(call_vm_read_overwrite__dst, "vm_read_overwrite (dst)");

	RUN_NEW(call_mach_vm_write__src, "mach_vm_write (src)");
	RUN_NEW(call_mach_vm_write__dst, "mach_vm_write (dst)");
	RUN_OLD(call_vm_write__src, "vm_write (src)");
	RUN_OLD(call_vm_write__dst, "vm_write (dst)");

	RUN_NEW(call_mach_vm_copy__src, "mach_vm_copy (src)");
	RUN_NEW(call_mach_vm_copy__dst, "mach_vm_copy (dst)");
	RUN_OLD(call_vm_copy__src, "vm_copy (src)");
	RUN_OLD(call_vm_copy__dst, "vm_copy (dst)");
#undef RUN_NEW
#undef RUN_OLD

	/*
	 * -- inherit functions --
	 */

#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_start_size(fn, name " (start/size)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_inherit, "mach_vm_inherit");
	RUN_OLD(call_vm_inherit, "vm_inherit");
#undef RUN_OLD
#undef RUN_NEW

#define RUN(fn, name) dealloc_results(process_results(test_unix_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_minherit, "minherit");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_vm_inherit_t(fn, name " (vm_inherit_t)")))
	RUN(call_mach_vm_inherit__inherit, "mach_vm_inherit");
#undef RUN
#define RUN(fn, name) dealloc_results(process_results(test_unix_with_allocated_vm_inherit_t(fn, name " (vm_inherit_t)")))
	RUN(call_minherit__inherit, "minherit");
#undef RUN

	/*
	 * -- protection functions --
	 */

#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_start_size(fn, name " (start/size)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_protect__start_size, "mach_vm_protect");
	RUN_OLD(call_vm_protect__start_size, "vm_protect");
#undef RUN_NEW
#undef RUN_OLD
#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_protect__vm_prot, "mach_vm_protect");
	RUN_OLD(call_vm_protect__vm_prot, "vm_protect");
#undef RUN_NEW
#undef RUN_OLD
#define RUN(fn, name) dealloc_results(process_results(test_unix_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_mprotect__start_size, "mprotect");
#undef RUN
#define RUN(fn, name) dealloc_results(process_results(test_unix_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
	RUN(call_mprotect__vm_prot, "mprotect");
#undef RUN

	/*
	 * -- madvise/behavior functions --
	 */

	unsigned alignment_for_can_reuse;
	if (isRosetta()) {
		/*
		 * VM_BEHAVIOR_CAN_REUSE and MADV_CAN_REUSE get different errors
		 * on Rosetta when the allocation happens to be 4K vs 16K aligned.
		 * Force 16K alignment for consistent results.
		 */
		alignment_for_can_reuse = KB16 - 1;
	} else {
		/* Use default alignment everywhere else. */
		alignment_for_can_reuse = 0;
	}

#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_start_size(fn, name " (start/size)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_behavior_set__start_size__default, "mach_vm_behavior_set (VM_BEHAVIOR_DEFAULT)");
	RUN_OLD(call_vm_behavior_set__start_size__default, "vm_behavior_set (VM_BEHAVIOR_DEFAULT)");
#undef RUN_NEW
#undef RUN_OLD

#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_aligned_start_size(fn, alignment_for_can_reuse, name " (start/size)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_aligned_start_size(fn, alignment_for_can_reuse, name " (start/size)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_behavior_set__start_size__can_reuse, "mach_vm_behavior_set (VM_BEHAVIOR_CAN_REUSE)");
	RUN_OLD(call_vm_behavior_set__start_size__can_reuse, "vm_behavior_set (VM_BEHAVIOR_CAN_REUSE)");
#undef RUN_NEW
#undef RUN_OLD

#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_aligned_vm_behavior_t(fn, alignment_for_can_reuse, name " (vm_behavior_t)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_aligned_vm_behavior_t(fn, alignment_for_can_reuse, name " (vm_behavior_t)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_behavior_set__vm_behavior, "mach_vm_behavior_set");
	RUN_OLD(call_vm_behavior_set__vm_behavior, "vm_behavior_set");
#undef RUN_NEW
#undef RUN_OLD

#define RUN(fn, name) dealloc_results(process_results(test_unix_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_madvise__start_size, "madvise");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_unix_with_allocated_aligned_vm_advise_t(fn, alignment_for_can_reuse, name " (vm_advise_t)")))
	RUN(call_madvise__vm_advise, "madvise");
#undef RUN

	/*
	 * -- msync functions --
	 */

#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_start_size(fn, name " (start/size)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_msync__start_size, "mach_vm_msync");
	RUN_OLD(call_vm_msync__start_size, "vm_msync");
#undef RUN_NEW
#undef RUN_OLD
#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_vm_sync_t(fn, name " (vm_sync_t)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_vm_sync_t(fn, name " (vm_sync_t)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_msync__vm_sync, "mach_vm_msync");
	RUN_OLD(call_vm_msync__vm_sync, "vm_msync");
#undef RUN_NEW
#undef RUN_OLD
#define RUN(fn, name) dealloc_results(process_results(test_unix_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_msync__start_size, "msync");
	RUN(call_msync_nocancel__start_size, "msync_nocancel");
#undef RUN
#define RUN(fn, name) dealloc_results(process_results(test_unix_with_allocated_vm_msync_t(fn, name " (msync flags)")))
	RUN(call_msync__vm_msync, "msync");
	RUN(call_msync_nocancel__vm_msync, "msync_nocancel");
#undef RUN

	/*
	 * -- machine attribute functions --
	 */

#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_start_size(fn, name " (start/size)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_machine_attribute__start_size, "mach_vm_machine_attribute");
	RUN_OLD(call_vm_machine_attribute__start_size, "vm_machine_attribute");
#undef RUN_NEW
#undef RUN_OLD
#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_vm_machine_attribute_t(fn, name " (machine_attribute_t)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_vm_machine_attribute_t(fn, name " (machine_attribute_t)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_machine_attribute__machine_attribute, "mach_vm_machine_attribute");
	RUN_OLD(call_vm_machine_attribute__machine_attribute, "vm_machine_attribute");
#undef RUN_NEW
#undef RUN_OLD

	/*
	 * -- purgability/purgeability functions --
	 */

#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_purgeable_addr(fn, name " (addr)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_purgeable_addr(fn, name " (addr)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_purgable_control__address__get, "mach_vm_purgable_control (get)");
	RUN_OLD(call_vm_purgable_control__address__get, "vm_purgable_control (get)");

	RUN_NEW(call_mach_vm_purgable_control__address__purge_all, "mach_vm_purgable_control (purge all)");
	RUN_OLD(call_vm_purgable_control__address__purge_all, "vm_purgable_control (purge all)");
#undef RUN_NEW
#undef RUN_OLD
#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_purgeable_and_state(fn, name " (purgeable and state)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_purgeable_and_state(fn, name " (purgeable and state)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_purgable_control__purgeable_state, "mach_vm_purgable_control");
	RUN_OLD(call_vm_purgable_control__purgeable_state, "vm_purgable_control");
#undef RUN_NEW
#undef RUN_OLD

	/*
	 * -- region info functions --
	 */

#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_addr(fn, name " (addr)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_addr(fn, name " (addr)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_region, "mach_vm_region");
	RUN_OLD(call_vm_region, "vm_region");
	RUN_NEW(call_mach_vm_region_recurse, "mach_vm_region_recurse");
	RUN_OLD(call_vm_region_recurse, "vm_region_recurse");
	RUN_OLD(call_vm_region_recurse_64, "vm_region_recurse_64");
#undef RUN_NEW
#undef RUN_OLD

	/*
	 * -- page info functions --
	 */

#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_addr(fn, name " (addr)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(process_results(test_oldmach_with_allocated_addr(fn, name " (addr)")))
#else
#define RUN_OLD(fn, name) do {} while (0)
#endif
	RUN_NEW(call_mach_vm_page_info, "mach_vm_page_info");
	RUN_NEW(call_mach_vm_page_query, "mach_vm_page_query");
	RUN_OLD(call_vm_map_page_query, "vm_map_page_query");
#undef RUN_NEW
#undef RUN_OLD

#define RUN_NEW(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
	RUN_NEW(call_mach_vm_page_range_query, "mach_vm_page_range_query");
#undef RUN_NEW

#define RUN(fn, name) dealloc_results(process_results(test_unix_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_mincore, "mincore");
#undef RUN

	/*
	 * -- miscellaneous functions --
	 */

#define RUN(fn, name) dealloc_results(process_results(test_unix_shared_region_map_and_slide_2_np(fn, name " (files/mappings)")))
	RUN(call_shared_region_map_and_slide_2_np_child, "shared_region_map_and_slide_2_np");
	RUN(call_shared_region_map_and_slide_2_np_in_thread, "different thread shared_region_map_and_slide_2_np");
#undef RUN

#if 0
#define RUN(fn, name) dealloc_results(process_results(test_mach_vm_deferred_reclamation_buffer_init(fn, name)))
	RUN(call_mach_vm_deferred_reclamation_buffer_init, "mach_vm_deferred_reclamation_buffer_init");
#undef RUN
#endif

out:
	restore_exc_guard();

	if (generate_golden) {
		if (!out_param_bad_count || (dump && !should_test_results)) {
			// Print after verified there is not OUT_PARAM_BAD results before printing,
			// or user explicitly set DUMP_RESULTS=1 GENERATE_GOLDEN_IMAGE=1
			printf("%s", GOLDEN_OUTPUT_START);
		}
	}
	free(GOLDEN_OUTPUT_START);

	if (dump_golden || should_test_results) {
		clean_golden_results();
	}

	if (reenable_vm_sanitize_telemetry() != 0) {
		T_FAIL("Failed to reenable VM API telemetry.");
		return;
	}

	T_PASS("vm parameter validation userspace");
}


/////////////////////////////////////////////////////
// Kernel test invocation.
// The actual test code is in:
// osfmk/tests/vm_parameter_validation_kern.c

#define KERN_RESULT_DELIMITER "\n"

#ifndef STRINGIFY
#define __STR(x)        #x
#define STRINGIFY(x)    __STR(x)
#endif

// Verify golden list being generated doesn't contain OUT_BAD_PARAM
static int
out_bad_param_in_kern_golden_results(char *kern_buffer)
{
	const char *out_param_bad_str = STRINGIFY(OUT_PARAM_BAD);
	char *out_param_bad_match = strstr(kern_buffer, out_param_bad_str);
	if (out_param_bad_match) {
		T_FAIL("Out parameter violation return code (%s) found in results, aborting.\n", out_param_bad_str);
		return 1;
	}
	return 0;
}


// Read results written by __dump_results()
static int
populate_kernel_results(char *kern_buffer)
{
	char *line = NULL;
	char *sub_line = NULL;
	char *test_name = NULL;
	char *result_name = NULL;
	char *token = NULL;
	char *s_num_kern_results = NULL;
	results_t *kern_results = NULL;
	uint32_t num_kern_results = 0;
	uint32_t result_number = 0;
	int result_ret = 0;
	bool in_test = FALSE;

	line = strtok(kern_buffer, KERN_RESULT_DELIMITER);
	while (line != NULL) {
		if (strncmp(line, TESTNAME_DELIMITER, strlen(TESTNAME_DELIMITER)) == 0) {
			sub_line = line + strlen(TESTNAME_DELIMITER);
			test_name = strdup(sub_line);
			result_number = 0;
			in_test = TRUE;
		} else if (in_test && strncmp(line, RESULTCOUNT_DELIMITER, strlen(RESULTCOUNT_DELIMITER)) == 0) {
			s_num_kern_results = line + strlen(RESULTCOUNT_DELIMITER);
			num_kern_results = (uint32_t)strtoul(s_num_kern_results, NULL, 10);
			kern_results = alloc_results(test_name, eUNKNOWN_TRIALS, num_kern_results);
			kern_results->count = num_kern_results;
			kern_list[num_kern_tests++] = kern_results;
		} else if (in_test && strncmp(line, TESTCONFIG_DELIMITER, strlen(TESTCONFIG_DELIMITER)) == 0) {
			sub_line = line + strlen(TESTCONFIG_DELIMITER);
			kern_results->testconfig = strdup(sub_line);
		} else if (in_test && strstr(line, KERN_TESTRESULT_DELIMITER)) {
			// should have found TESTCONFIG already
			assert(kern_results->testconfig != NULL);
			sscanf(line, KERN_TESTRESULT_DELIMITER "%d", &result_ret);
			// get result name (comes after the first ,)
			token = strchr(line, ',');
			if (token) {
				token = token + 2; // skip the , and the extra space
				result_name = strdup(token);
				if (result_number >= num_kern_results) {
					T_LOG("\tKERN Invalid output in test %s, seeing more results (%u) than expected (%u), ignoring trial RESULT %d, %s\n",
					    test_name, result_number, num_kern_results, result_ret, result_name);
					free(result_name);
				} else {
					kern_results->list[result_number++] = (result_t){.ret = result_ret, .name = result_name};
				}
			}
		} else {
			// T_LOG("Unknown kernel result line: %s\n", line);
			//in_test = FALSE;
		}

		line = strtok(NULL, KERN_RESULT_DELIMITER);
	}

	dump_kernel_results_list();

	return 0;
}

static int64_t
run_sysctl_test(const char *t, int64_t value)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", t);
	return result;
}

T_DECL(vm_parameter_validation_kern,
    "parameter validation for kext/xnu calls",
    T_META_SPAWN_TOOL(DECOMPRESS),
    T_META_SPAWN_TOOL_ARG("kern"),
    T_META_SPAWN_TOOL_ARG(TMP_DIR),
    T_META_SPAWN_TOOL_ARG(GOLDEN_FILES_VERSION)
    )
{
	if (disable_vm_sanitize_telemetry() != 0) {
		T_FAIL("Could not disable VM API telemetry. Bailing out early.");
		return;
	}

	read_env();

	T_LOG("dump %d, golden %d, dump_golden %d, test %d\n", dump, generate_golden, dump_golden, should_test_results);

	disable_exc_guard();

	if (dump_golden) {
		if (populate_golden_results(KERN_GOLDEN_FILE)) {
			// couldn't load golden test results
			T_FAIL("Could not load golden file '%s'\n", KERN_GOLDEN_FILE);
			goto out;
		}

		// just print the parsed golden file
		for (uint32_t x = 0; x < num_tests; ++x) {
			__dump_results(golden_list[x]);
		}
		clean_golden_results();
		goto out;
	}

	T_LOG("Running kernel tests\n");

	// We allocate a large buffer. The kernel-side code writes output to it.
	// Then we print that output. This is faster than making the kernel-side
	// code print directly to the serial console, which takes many minutes
	// to transfer our test output at 14.4 KB/s.
	// We align this buffer to KB16 to allow the lower bits to be used for a fd.
	void *output;
	int alloc_failed = posix_memalign(&output, KB16, SYSCTL_OUTPUT_BUFFER_SIZE);
	assert(alloc_failed == 0);

	memset(output, 0, SYSCTL_OUTPUT_BUFFER_SIZE);

	int fd = get_fd();
	assert((fd & ((int)KB16 - 1)) == fd);
	if (generate_golden) {
		// pass flag on the msb of the fd
		assert((fd & ((int)(KB16 >> 1) - 1)) == fd);
		fd |=  KB16 >> 1;
	}
	int64_t result = run_sysctl_test("vm_parameter_validation_kern", (int64_t)output + fd);

	T_QUIET; T_EXPECT_EQ(1ull, result, "vm_parameter_validation_kern");

	if (generate_golden) {
		if (!out_bad_param_in_kern_golden_results(output) || (dump && !should_test_results)) {
			// Print after verified there is not OUT_PARAM_BAD results before printing,
			// or user explicitly set DUMP_RESULTS=1 GENERATE_GOLDEN_IMAGE=1
			printf("%s", output);
		}
		free(output);
		output = NULL;
	} else {
		// recreate a results_t to compare against the golden file results
		if (populate_kernel_results(output)) {
			T_FAIL("Error while parsing results\n");
		}
		free(output);
		output = NULL;

		if (should_test_results && populate_golden_results(KERN_GOLDEN_FILE)) {
			// couldn't load golden test results
			T_FAIL("Could not load golden file '%s'\n", KERN_GOLDEN_FILE);
			clean_kernel_results();
			goto out;
		}

		// compare results against values from golden list
		for (uint32_t x = 0; x < num_kern_tests; ++x) {
			process_results(kern_list[x]);
			dealloc_results(kern_list[x]);
			kern_list[x] = NULL;
		}
		clean_golden_results();
	}

out:
	restore_exc_guard();

	if (reenable_vm_sanitize_telemetry() != 0) {
		T_FAIL("Failed to reenable VM API telemetry.");
		return;
	}

	T_PASS("vm parameter validation kern");
}
