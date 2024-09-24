#include <darwintest.h>
#include <darwintest_utils.h>
#include <test_utils.h>

#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/memory_entry.h>
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

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
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
_Alignas(KB16) char guard_page[KB16];

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

static kern_return_t
call_munmap(MAP_T map __unused, mach_vm_address_t start, mach_vm_size_t size)
{
	int err = munmap((void*)start, (size_t)size);
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
make_a_mem_object(vm_size_t size)
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
	        mach_port_t invalid_value = INVALID_INITIAL_MACH_PORT;            \
	        mach_port_t out_handle = invalid_value;                           \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_ONLY, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                (void)mach_port_deallocate(mach_task_self(), out_handle); \
	/* MAP_MEM_ONLY doesn't use the size. It should not change it. */         \
	                assert(io_size == size);                                  \
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
	        mach_port_t invalid_value = INVALID_INITIAL_MACH_PORT;            \
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
	        mach_port_t invalid_value = INVALID_INITIAL_MACH_PORT;            \
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
	        mach_port_t invalid_value = INVALID_INITIAL_MACH_PORT;            \
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
	        mach_port_t invalid_value = INVALID_INITIAL_MACH_PORT;            \
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
	        mach_port_t invalid_value = INVALID_INITIAL_MACH_PORT;            \
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
	        mach_port_t invalid_value = INVALID_INITIAL_MACH_PORT;  \
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
	        mach_port_t invalid_value = INVALID_INITIAL_MACH_PORT;  \
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
	vm_offset_t out_addr = INVALID_INITIAL_ADDRESS;
	mach_msg_type_number_t out_size = INVALID_INITIAL_SIZE;
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
	vm_offset_t out_addr = INVALID_INITIAL_ADDRESS;
	mach_msg_type_number_t out_size = INVALID_INITIAL_SIZE;
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
call_vm_read_overwrite__ssz(MAP_T map, mach_vm_address_t start, mach_vm_address_t start_2, mach_vm_size_t size)
{
	vm_size_t out_size;
	kern_return_t kr = vm_read_overwrite(map, (vm_address_t) start, (vm_size_t) size, (vm_address_t) start_2, &out_size);
	check_vm_read_overwrite_outparam_changes(&kr, out_size, size);
	return kr;
}

static kern_return_t
call_vm_read_overwrite__src(MAP_T map, mach_vm_address_t src, mach_vm_size_t size)
{
	vm_size_t out_size;
	allocation_t dst SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = vm_read_overwrite(map, (vm_address_t) src, (vm_size_t) size, (vm_address_t) dst.addr, &out_size);
	check_vm_read_overwrite_outparam_changes(&kr, out_size, size);
	return kr;
}

static kern_return_t
call_vm_read_overwrite__dst(MAP_T map, mach_vm_address_t dst, mach_vm_size_t size)
{
	vm_size_t out_size;
	allocation_t src SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = vm_read_overwrite(map, (vm_address_t) src.addr, (vm_size_t) size, (vm_address_t) dst, &out_size);
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
call_vm_copy__src(MAP_T map, mach_vm_address_t src, mach_vm_size_t size)
{
	allocation_t dst SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = vm_copy(map, (vm_address_t) src, (vm_size_t) size, (vm_address_t) dst.addr);
	return kr;
}

static kern_return_t
call_vm_copy__dst(MAP_T map, mach_vm_address_t dst, mach_vm_size_t size)
{
	allocation_t src SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	kern_return_t kr = vm_copy(map, (vm_address_t) src.addr, (vm_size_t) size, (vm_address_t) dst);
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
	void *rv = mmap_wrapper((void *)start, size, prot, flags, fd, 0);
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
	void *rv = mmap_wrapper((void *)start, size, VM_PROT_DEFAULT, mmap_flags, kernel_flags, 0);
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
	void *rv = mmap_wrapper((void *)dst, size, VM_PROT_DEFAULT, flags, fd, (off_t)fileoff);
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
	void *rv = mmap_wrapper((void *)start, size, VM_PROT_DEFAULT, flags, fd, 0);
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
	void *rv = mmap_wrapper((void *)0, size, VM_PROT_DEFAULT, flags, fd, (off_t)offset);
	if (rv == MAP_FAILED) {
		return errno;
	} else {
		assert(0 == munmap_helper(rv, size));
		return 0;
	}
}

#define IMPL_ONE_FROM_HELPER(type, variant, flags, ...)                                                                                 \
	static kern_return_t                                                                                                            \
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
	void *rv = mmap_wrapper((void *)start, size, VM_PROT_DEFAULT, mmap_flags, fd, 0);
	if (rv == MAP_FAILED) {
		return errno;
	} else {
		assert(0 == munmap(rv, size));
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
	if (!range_overflows_strict_zero(trial.start, trial.size, VM_MAP_PAGE_MASK(map))) {
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

static kern_return_t
call_vm_deallocate(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	kern_return_t kr = vm_deallocate(map, (vm_address_t) start, (vm_size_t) size);
	return kr;
}


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

static results_t *
test_mach_allocated_with_vm_inherit_t(kern_return_t (*func)(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_inherit_t flags), const char * testname)
{
	MAP_T map SMART_MAP;
	allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	vm_inherit_trials_t * trials SMART_VM_INHERIT_TRIALS();
	results_t *results = alloc_results(testname, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		int ret = func(map, base.addr, base.size, trials->list[i].value);
		append_result(results, ret, trials->list[i].name);
	}
	return results;
}


static results_t *
test_unix_allocated_with_vm_inherit_t(kern_return_t (*func)(mach_vm_address_t start, mach_vm_size_t size, vm_inherit_t flags), const char * testname)
{
	MAP_T map SMART_MAP;
	allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	vm_inherit_trials_t * trials SMART_VM_INHERIT_TRIALS();
	results_t *results = alloc_results(testname, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		int ret = func(base.addr, base.size, trials->list[i].value);
		append_result(results, ret, trials->list[i].name);
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
#define GOLDEN_FILES_VERSION "vm_parameter_validation_golden_images_168d625.tar.xz"
#define TMP_DIR "/tmp/"
#define ASSETS_DIR "../assets/vm_parameter_validation/"
#define DECOMPRESS ASSETS_DIR "decompress.sh"
#define GOLDEN_FILE TMP_DIR "user_golden_image.log"

#define KERN_GOLDEN_FILE TMP_DIR "kern_golden_image.log"
#define KERN_MAX_UNKNOWN_TEST_RESULTS    64

results_t *golden_list[MAX_NUM_TESTS];
results_t *kern_list[MAX_NUM_TESTS];

// Read results written by dump_golden_results().
static int
populate_golden_results(const char *filename)
{
	FILE *file;
	char line[MAX_LINE_LENGTH];
	results_t *results = NULL;
	uint32_t num_results = 0;
	uint32_t result_number = 0;
	int result_ret = 0;
	char *test_name = NULL;
	char *sub_line = NULL;
	char *s_num_results = NULL;
	bool in_test = FALSE;

	// cd to the directory containing this executable
	// Test files are located relative to there.
	uint32_t exesize = 0;
	_NSGetExecutablePath(NULL, &exesize);
	char *exe = malloc(exesize);
	_NSGetExecutablePath(exe, &exesize);
	char *dir = dirname(exe);
	chdir(dir);
	free(exe);

	file = fopen(filename, "r");
	if (file == NULL) {
		T_LOG("Could not open file %s\n", filename);
		return 1;
	}

	// Read file line by line
	while (fgets(line, MAX_LINE_LENGTH, file) != NULL) {
		// Check if the line starts with "TESTNAME" or "RESULT COUNT"
		if (strncmp(line, TESTNAME_DELIMITER, strlen(TESTNAME_DELIMITER)) == 0) {
			// remove the newline char
			line[strcspn(line, "\r")] = 0;
			sub_line = line + strlen(TESTNAME_DELIMITER);
			test_name = strdup(sub_line);
			// T_LOG("TESTNAME %u : %s", num_tests, test_name);
			in_test = TRUE;
		} else if (in_test && strncmp(line, RESULTCOUNT_DELIMITER, strlen(RESULTCOUNT_DELIMITER)) == 0) {
			assert(num_tests < MAX_NUM_TESTS);
			s_num_results = line + strlen(RESULTCOUNT_DELIMITER);
			num_results = (uint32_t)strtoul(s_num_results, NULL, 10);
			results = alloc_results(test_name, num_results);
			results->count = num_results;
			golden_list[num_tests++] = results;
			// T_LOG("num_tests %u, testname %s, count: %u", num_tests, results->testname, results->count);
		} else if (in_test && strncmp(line, TESTRESULT_DELIMITER, strlen(TESTRESULT_DELIMITER)) == 0) {
			// T_LOG("checking: %s\n", line);
			sscanf(line, "%d: %d", &result_number, &result_ret);
			assert(result_number < num_results);
			// T_LOG("\tresult #%u: %d\n", result_number, result_ret);
			results->list[result_number] = (result_t){.ret = result_ret};
		} else {
			// T_LOG("Unknown line: %s\n", line);
			in_test = FALSE;
		}
	}

	fclose(file);

	dump_golden_list();

	return 0;
}

static void
clean_golden_results()
{
	for (uint32_t x = 0; x < num_tests; ++x) {
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

// Verbose output in dump_results, controlled by DUMP_RESULTS env.
bool dump = FALSE;
// Output to create a golden test result, controlled by GENERATE_GOLDEN_IMAGE.
bool generate_golden = FALSE;
// Run tests as tests (i.e. emit TS_{PASS/FAIL}), enabled unless golden image generation is true.
bool test_results =  TRUE;

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

	T_LOG("dump %d, golden %d, test %d\n", dump, generate_golden, test_results);

	if (generate_golden && unsigned_code_is_disallowed()) {
		// Some test results change when SIP is enabled.
		// Golden files must record the SIP-disabled values.
		T_FAIL("Can't generate golden files with SIP enabled. Disable SIP and try again.\n");
		return;
	}

	if (test_results && populate_golden_results(GOLDEN_FILE)) {
		// bail out early, couldn't load golden test results
		T_FAIL("Could not open golden file '%s'\n", GOLDEN_FILE);
		return;
	}

	set_up_guard_page();

	disable_exc_guard();

	/*
	 * Group 1: memory entry
	 */

	// Mach start/size with both old-style and new-style types
	// (co-located so old and new can be compared more easily)
#define RUN_NEW(fn, name) dealloc_results(dump_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(dump_results(test_oldmach_with_allocated_start_size(fn, name " (start/size)")))
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

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_size(fn, name " (size)")))
	RUN(call_mach_memory_object_memory_entry_64__size, "mach_memory_object_memory_entry_64");
	RUN(call_replacement_mach_memory_object_memory_entry__size, "mach_memory_object_memory_entry");
#undef RUN

#define RUN_NEW(fn, name) dealloc_results(dump_results(test_mach_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
#define RUN_OLD(fn, name) dealloc_results(dump_results(test_oldmach_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
#define RUN_OLD64(fn, name) RUN_NEW(fn, name)

	RUN_NEW(call_mach_make_memory_entry_64__vm_prot, "mach_make_memory_entry_64");
#if TEST_OLD_STYLE_MACH
	RUN_OLD(call_mach_make_memory_entry__vm_prot, "mach_make_memory_entry");
	RUN_OLD64(call__mach_make_memory_entry__vm_prot, "_mach_make_memory_entry");
#endif

#undef RUN_NEW
#undef RUN_OLD
#undef RUN_OLD64

#define RUN(fn, name) dealloc_results(dump_results(test_mach_vm_prot(fn, name " (vm_prot_t)")))
	RUN(call_mach_memory_object_memory_entry_64__vm_prot, "mach_memory_object_memory_entry_64");
	RUN(call_replacement_mach_memory_object_memory_entry__vm_prot, "mach_memory_object_memory_entry");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_ledger_tag(fn, name " (ledger tag)")))
	RUN(call_mach_memory_entry_ownership__ledger_tag, "mach_memory_entry_ownership");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_ledger_flag(fn, name " (ledger flag)")))
	RUN(call_mach_memory_entry_ownership__ledger_flag, "mach_memory_entry_ownership");
#undef RUN

	/*
	 * Group 2: allocate/deallocate
	 */

#define RUN(fn, name) dealloc_results(dump_results(test_mach_allocation_func_with_start_size(fn, name)))
	RUN(call_mach_vm_allocate__start_size_fixed, "mach_vm_allocate (fixed) (realigned start/size)");
	RUN(call_mach_vm_allocate__start_size_anywhere, "mach_vm_allocate (anywhere) (hint/size)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_allocation_func_with_vm_map_kernel_flags_t(fn, name " (vm_map_kernel_flags_t)")))
	RUN(call_mach_vm_allocate__flags, "mach_vm_allocate");
#undef RUN

	dealloc_results(dump_results(test_deallocator(call_mach_vm_deallocate, "mach_vm_deallocate (start/size)")));
#if TEST_OLD_STYLE_MACH
	dealloc_results(dump_results(test_deallocator(call_vm_deallocate, "vm_deallocate (start/size)")));
#endif

#define RUN(fn, name) dealloc_results(dump_results(test_deallocator(fn, name " (start/size)")))
	RUN(call_munmap, "munmap");
#undef RUN

	/*
	 * Group 3: map/unmap
	 */

	// map tests

#define RUN_START_SIZE(fn, name) dealloc_results(dump_results(test_mach_with_allocated_start_size(fn, name " (realigned start/size)")))
#define RUN_HINT_SIZE(fn, name) dealloc_results(dump_results(test_mach_with_allocated_start_size(fn, name " (hint/size)")))
#define RUN_PROT_PAIR(fn, name) dealloc_results(dump_results(test_mach_vm_prot_pair(fn, name " (prot_pairs)")))
#define RUN_INHERIT(fn, name) dealloc_results(dump_results(test_mach_with_allocated_vm_inherit_t(fn, name " (vm_inherit_t)")))
#define RUN_FLAGS(fn, name) dealloc_results(dump_results(test_mach_allocation_func_with_vm_map_kernel_flags_t(fn, name " (vm_map_kernel_flags_t)")))
#define RUN_SSOO(fn, name) dealloc_results(dump_results(test_mach_with_start_size_offset_object(fn, name " (start/size/offset/object)")))

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
#define RUN_HELPER(harness, fn, variant, type, type_name, name) dealloc_results(dump_results(harness(FN_NAME(fn, variant, type), #name " (" #variant ") (" type_name ")")))
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

#define RUN(fn, name) dealloc_results(dump_results(test_mmap_with_allocated_vm_map_kernel_flags_t(fn, name " (kernel flags)")))
	RUN(call_mmap__anon_private__kernel_flags, "mmap (anon private)");
	RUN(call_mmap__anon_shared__kernel_flags, "mmap (anon shared)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_allocated_mmap_flags(fn, name " (mmap flags)")))
	RUN(call_mmap__mmap_flags, "mmap");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_allocated_start_size(fn, name " (hint/size)")))
	RUN(call_mmap__file_private__start_size, "mmap (file private)");
	RUN(call_mmap__anon_private__start_size, "mmap (anon private)");
	RUN(call_mmap__file_shared__start_size, "mmap (file shared)");
	RUN(call_mmap__anon_shared__start_size, "mmap (anon shared)");
	RUN(call_mmap__file_private_codesign__start_size, "mmap (file private codesign)");
	RUN(call_mmap__file_private_media__start_size, "mmap (file private media)");
	RUN(call_mmap__nounix03_private__start_size, "mmap (no unix03)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_fixed_dst_size(fn, name " (dst/size)")))
	RUN(call_mmap__fixed_private__start_size, "mmap (fixed)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_allocated_start_size(fn, name " (offset/size)")))
	RUN(call_mmap__file_private__offset_size, "mmap (file private)");
	RUN(call_mmap__anon_private__offset_size, "mmap (anon private)");
	RUN(call_mmap__file_shared__offset_size, "mmap (file shared)");
	RUN(call_mmap__anon_shared__offset_size, "mmap (anon shared)");
	RUN(call_mmap__file_private_codesign__offset_size, "mmap (file private codesign)");
	RUN(call_mmap__file_private_media__offset_size, "mmap (file private media)");
	RUN(call_mmap__nounix03_private__offset_size, "mmap (no unix03)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_dst_size_fileoff(fn, name " (hint/size/fileoff)")))
	RUN(call_mmap__file_private__dst_size_fileoff, "mmap (file private)");
	RUN(call_mmap__anon_private__dst_size_fileoff, "mmap (anon private)");
	RUN(call_mmap__file_shared__dst_size_fileoff, "mmap (file shared)");
	RUN(call_mmap__anon_shared__dst_size_fileoff, "mmap (anon shared)");
	RUN(call_mmap__file_private_codesign__dst_size_fileoff, "mmap (file private codesign)");
	RUN(call_mmap__file_private_media__dst_size_fileoff, "mmap (file private media)");
	RUN(call_mmap__nounix03_private__dst_size_fileoff, "mmap (no unix03)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_fixed_dst_size_fileoff(fn, name " (dst/size/fileoff)")))
	RUN(call_mmap__fixed_private__dst_size_fileoff, "mmap (fixed)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
	RUN(call_mmap__file_private__vm_prot, "mmap (file private)");
	RUN(call_mmap__anon_private__vm_prot, "mmap (anon private)");
	RUN(call_mmap__file_shared__vm_prot, "mmap (file shared)");
	RUN(call_mmap__anon_shared__vm_prot, "mmap (anon shared)");
	RUN(call_mmap__file_private_codesign__vm_prot, "mmap (file private codesign)");
	RUN(call_mmap__file_private_media__vm_prot, "mmap (file private media)");
	RUN(call_mmap__nounix03_private__vm_prot, "mmap (no unix03)");
	RUN(call_mmap__fixed_private__vm_prot, "mmap (fixed)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_unix_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_mremap_encrypted, "mremap_encrypted");
#undef RUN

	/*
	 * Group 4: wire/unwire
	 */

#define RUN(fn, name) dealloc_results(dump_results(test_unix_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_mlock, "mlock");
	RUN(call_munlock, "munlock");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_mach_vm_wire__wire, "mach_vm_wire (wire)");
	RUN(call_replacement_vm_wire__wire, "vm_wire (wire)");
	RUN(call_mach_vm_wire__unwire, "mach_vm_wire (unwire)");
	RUN(call_replacement_vm_wire__unwire, "vm_wire (unwire)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
	RUN(call_mach_vm_wire__vm_prot, "mach_vm_wire");
	RUN(call_replacement_vm_wire__vm_prot, "vm_wire");
#undef RUN

	/*
	 * Group 5: copyin/copyout
	 */

#define RUN_NEW(fn, name) dealloc_results(dump_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
#if TEST_OLD_STYLE_MACH
#define RUN_OLD(fn, name) dealloc_results(dump_results(test_oldmach_with_allocated_start_size(fn, name " (start/size)")))
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

	restore_exc_guard();

	if (test_results) {
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

// Read results written by __dump_results()
static int
populate_kernel_results(char *kern_buffer)
{
	char *line = NULL;
	char *sub_line = NULL;
	char *test_name = NULL;
	char *result_name = NULL;
	char *token = NULL;
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
			// Some test trials are up to 614656 combinations, use count from golden list if possible.
			// Otherwise just get a small number of them (full results can be printed with DUMP=1)
			num_kern_results = KERN_MAX_UNKNOWN_TEST_RESULTS;
			results_t *golden_result = test_name_to_golden_results(test_name);
			if (golden_result) {
				num_kern_results = golden_result->count;
			} else {
				T_LOG("kern %s not found in golden list\n", test_name);
			}
			kern_results = alloc_results(test_name, NULL, num_kern_results);
			kern_results->count = num_kern_results;
			kern_list[num_kern_tests++] = kern_results;
			result_number = 0;
			in_test = TRUE;
		} else if (in_test && strncmp(line, TESTCONFIG_DELIMITER, strlen(TESTCONFIG_DELIMITER)) == 0) {
			assert(kern_results->testconfig == NULL);
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
					T_LOG("\tKERN Recreate Golden List? skipping result %d - %s from test %s\n", result_ret, result_name, test_name);
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

	// Check if kernel will return using golding list format.
	int64_t kern_golden_arg = 0;
	if (os_parse_boot_arg_int("vm_parameter_validation_kern_golden", &kern_golden_arg)) {
		T_LOG("vm_parameter_validation_kern_golden=%lld found in boot args\n", kern_golden_arg);
		generate_golden |= (kern_golden_arg == 1);
	}

	T_LOG("dump %d, golden %d, test %d\n", dump, generate_golden, test_results);
	if (test_results && populate_golden_results(KERN_GOLDEN_FILE)) {
		// couldn't load golden test results
		T_FAIL("Could not open golden file '%s'\n", KERN_GOLDEN_FILE);
		return;
	}

	disable_exc_guard();

	T_LOG("Continue to test part\n");

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

	if (generate_golden || !test_results) {
		// just print the reduced list result
		printf("%s", output);
	} else {
		// recreate a results_t to compare against the golden file results
		if (populate_kernel_results(output)) {
			T_FAIL("Error while parsing results\n");
		}

		// compare results against values from golden list
		for (uint32_t x = 0; x < num_kern_tests; ++x) {
			dump_results(kern_list[x]);
		}
	}

	free(output);

	if (!generate_golden) {
		clean_kernel_results();
		clean_golden_results();
	}

	restore_exc_guard();

	if (reenable_vm_sanitize_telemetry() != 0) {
		T_FAIL("Failed to reenable VM API telemetry.");
		return;
	}

	T_PASS("vm parameter validation kern");
}
