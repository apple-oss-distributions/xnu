#ifndef VM_PARAMETER_VALIDATION_H
#define VM_PARAMETER_VALIDATION_H


/*
 * Common Naming Conventions:
 * call_* functions are harnesses used to call a single function under test.
 * They take all arguments needed to call the function and avoid calling functions with PANICing values.
 * test_* functions are used to call the call_ functions. They iterate through possibilities of interesting parameters
 * and provide those as arguments to the call_ functions.
 *
 * Common Abbreviations:
 * ssz: Start + Start + Size
 * ssoo: Start + Size + Offset + Object
 * sso: Start + Start + Offset
 */

#if KERNEL

#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <mach/mach_types.h>
#include <mach/mach_host.h>
#include <mach/memory_object.h>
#include <mach/memory_entry.h>
#include <mach/mach_vm_server.h>

#include <device/device_port.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <vm/memory_object.h>
#include <vm/vm_fault.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_kern_internal.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <vm/vm_memtag.h>
#include <vm/vm_memory_entry.h>
#include <vm/vm_memory_entry_xnu.h>
#include <vm/vm_object_internal.h>
#include <vm/vm_iokit.h>
#include <kern/ledger.h>
extern ledger_template_t        task_ledger_template;

// Temporary bridging of vm header rearrangement.
// Remove this after integration is complete.
#if 0  /* old style */

#define FLAGS_AND_TAG(f, t) f, t
#define vm_map_wire_and_extract vm_map_wire_and_extract_external

#else /* new style */

#define FLAGS_AND_TAG(f, t) ({                             \
	vm_map_kernel_flags_t vmk_flags;                   \
	vm_map_kernel_flags_set_vmflags(&vmk_flags, f, t); \
	vmk_flags;                                         \
})

#endif

#else  // KERNEL

#include <TargetConditionals.h>

#endif // KERNEL

// fixme re-enable -Wunused-function when we're done writing new tests
#pragma clang diagnostic ignored "-Wunused-function"

// ignore some warnings inside this file
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeclaration-after-statement"
#pragma clang diagnostic ignored "-Wincompatible-function-pointer-types"
#pragma clang diagnostic ignored "-Wmissing-prototypes"
#pragma clang diagnostic ignored "-Wpedantic"
#pragma clang diagnostic ignored "-Wgcc-compat"


#define INVALID_INITIAL_ADDRESS 0xabababab
/*
 * It's important for us to never have a test with a size like
 * INVALID_INITIAL_SIZE, and for this to stay non page aligned.
 * See comment in call_mach_memory_entry_map_size__start_size for more info
 */
#define INVALID_INITIAL_SIZE 0xabababab
#define INVALID_INITIAL_PPNUM 0xabababab
#define INVALID_INITIAL_MACH_PORT (mach_port_t) 0xbabababa
// This cannot possibly be a valid vm_map_copy_t as they are pointers
#define INVALID_INITIAL_COPY (vm_map_copy_t) (void *) -1

// output buffer size for kext/xnu sysctl tests
// note: 1 GB is too big for watchOS
static const int64_t SYSCTL_OUTPUT_BUFFER_SIZE = 512 * 1024 * 1024;  // 512 MB

// caller name (kernel/kext/userspace), used to label the output
#if KERNEL
#       define CALLER_NAME "kernel"
#else
#       define CALLER_NAME "userspace"
#endif

// os name, used to label the output
#if KERNEL
#       if XNU_TARGET_OS_OSX
#               define OS_NAME "macos"
#       elif XNU_TARGET_OS_IOS
#              define OS_NAME "ios"
#       elif XNU_TARGET_OS_TV
#               define OS_NAME "tvos"
#       elif XNU_TARGET_OS_WATCH
#               define OS_NAME "watchos"
#       elif XNU_TARGET_OS_BRIDGE
#               define OS_NAME "bridgeos"
#       else
#               define OS_NAME "unknown-os"
#       endif
#else
#       if TARGET_OS_OSX
#               define OS_NAME "macos"
#       elif TARGET_OS_MACCATALYST
#               define OS_NAME "catalyst"
#       elif TARGET_OS_IOS
#              define OS_NAME "ios"
#       elif TARGET_OS_TV
#               define OS_NAME "tvos"
#       elif TARGET_OS_WATCH
#               define OS_NAME "watchos"
#       elif TARGET_OS_BRIDGE
#               define OS_NAME "bridgeos"
#       else
#               define OS_NAME "unknown-os"
#       endif
#endif

// architecture name, used to label the output
#if KERNEL
#       if __i386__
#               define ARCH_NAME "i386"
#       elif __x86_64__
#               define ARCH_NAME "x86_64"
#       elif __arm64__ && __LP64__
#               define ARCH_NAME "arm64"
#       elif __arm64__ && !__LP64__
#               define ARCH_NAME "arm64_32"
#       elif __arm__
#               define ARCH_NAME "arm"
#       else
#               define ARCH_NAME "unknown-arch"
#       endif
#else
#       if TARGET_CPU_X86
#               define ARCH_NAME "i386"
#       elif TARGET_CPU_X86_64
#               define ARCH_NAME "x86_64"
#       elif TARGET_CPU_ARM64 && __LP64__
#               define ARCH_NAME "arm64"
#       elif TARGET_CPU_ARM64 && !__LP64__
#               define ARCH_NAME "arm64_32"
#       elif TARGET_CPU_ARM
#               define ARCH_NAME "arm"
#       else
#               define ARCH_NAME "unknown-arch"
#       endif
#endif

#if KERNEL
#       define MAP_T vm_map_t
#else
#       define MAP_T mach_port_t
#endif

// Mach has new-style functions with 64-bit address and size
// and old-style functions with pointer-size address and size.
// On U64 platforms both names send the same MIG message
// and run the same kernel code so we need not test both.
// On U32 platforms they are different inside the kernel.
// fixme for kext/kernel, verify that vm32 entrypoints are not used and not exported
#if KERNEL || __LP64__
#       define TEST_OLD_STYLE_MACH 0
#else
#       define TEST_OLD_STYLE_MACH 1
#endif

// always 64-bit: addr_t, mach_vm_address/size_t, memory_object_size/offset_t
// always 32-bit: mach_msg_type_number_t, natural_t
// pointer-size:  void*, vm_address_t, vm_size_t
typedef uint64_t addr_t;

// We often use 4KB or 16KB instead of PAGE_SIZE
// (for example using 16KB instead of PAGE_SIZE to avoid Rosetta complications)
#define KB4 ((addr_t)4*1024)
#define KB16 ((addr_t)16*1024)

// Allocation size commonly used in tests.
// This size is big enough that our trials of small
// address offsets and sizes will still fit inside it.
#define TEST_ALLOC_SIZE (4 * KB16)

// Magic return codes used for in-band signalling.
// These must avoid kern_return_t and errno values.
#define BUSTED        -99  // trial is broken
#define IGNORED       -98  // trial not performed for acceptable reasons
#define ZEROSIZE      -97  // trial succeeded because size==0 (FAKE tests only)
#define PANIC         -96  // trial not performed because it would provoke a panic
#define GUARD         -95  // trial not performed because it would provoke EXC_GUARD
#define ACCEPTABLE    -94  // trial should be considered successful no matter what the golden result is
#define OUT_PARAM_BAD -93  // trial has incorrect setting of out parameter values

static inline bool
is_fake_error(int err)
{
	return err == BUSTED || err == IGNORED || err == ZEROSIZE ||
	       err == PANIC || err == GUARD || err == OUT_PARAM_BAD;
}

// Return the count of a (non-decayed!) array.
#define countof(array) (sizeof(array) / sizeof((array)[0]))

#if !KERNEL
static inline uint64_t
VM_MAP_PAGE_SIZE(MAP_T map __unused)
{
	// fixme wrong for out-of-process maps
	// on platforms that support processes with two different page sizes
	return PAGE_SIZE;
}

static inline uint64_t
VM_MAP_PAGE_MASK(MAP_T map __unused)
{
	// fixme wrong for out-of-process maps
	// on platforms that support processes with two different page sizes
	return PAGE_MASK;
}
#endif


#define IMPL(T)                                                         \
	/* Round up to the given page mask. */                          \
	__attribute__((overloadable, used))                             \
	static inline T                                                 \
	round_up_mask(T addr, uint64_t pagemask) {                      \
	        return (addr + (T)pagemask) & ~((T)pagemask);           \
	}                                                               \
                                                                        \
	/* Round up to the given page size. */                          \
	__attribute__((overloadable, used))                             \
	static inline T                                                 \
	round_up_page(T addr, uint64_t pagesize) {                      \
	        return round_up_mask(addr, pagesize - 1);               \
	}                                                               \
                                                                        \
	/* Round up to the given map's page size. */                    \
	__attribute__((overloadable, used))                             \
	static inline T                                                 \
	round_up_map(MAP_T map, T addr) {                               \
	        return round_up_mask(addr, VM_MAP_PAGE_MASK(map));      \
	}                                                               \
                                                                        \
	/* Truncate to the given page mask. */                          \
	__attribute__((overloadable, used))                             \
	static inline T                                                 \
	trunc_down_mask(T addr, uint64_t pagemask)                      \
	{                                                               \
	        return addr & ~((T)pagemask);                           \
	}                                                               \
                                                                        \
	/* Truncate to the given page size. */                          \
	__attribute__((overloadable, used))                             \
	static inline T                                                 \
	trunc_down_page(T addr, uint64_t pagesize)                      \
	{                                                               \
	        return trunc_down_mask(addr, pagesize - 1);             \
	}                                                               \
                                                                        \
	/* Truncate to the given map's page size. */                    \
	__attribute__((overloadable, used))                             \
	static inline T                                                 \
	trunc_down_map(MAP_T map, T addr)                               \
	{                                                               \
	        return trunc_down_mask(addr, VM_MAP_PAGE_MASK(map));    \
	}                                                               \
                                                                        \
	__attribute__((overloadable, unavailable("use round_up_page instead"))) \
	extern T                                                        \
	round_up(T addr, uint64_t pagesize);                            \
	__attribute__((overloadable, unavailable("use trunc_down_page instead"))) \
	extern T                                                        \
	trunc_down(T addr, uint64_t pagesize);

IMPL(uint64_t)
IMPL(uint32_t)
#undef IMPL


// duplicate the logic of VM's vm_map_range_overflows()
// false == good start+size combo, true == bad combo
#define IMPL(T)                                                         \
	__attribute__((overloadable, used))                             \
	static bool                                                     \
	range_overflows_allow_zero(T start, T size, T pgmask)           \
	{                                                               \
	        if (size == 0) {                                        \
	                return false;                                   \
	        }                                                       \
                                                                        \
	        T sum;                                                  \
	        if (__builtin_add_overflow(start, size, &sum)) {        \
	                return true;                                    \
	        }                                                       \
                                                                        \
	        T aligned_start = trunc_down_mask(start, pgmask);       \
	        T aligned_end = round_up_mask(start + size, pgmask);    \
	        if (aligned_end <= aligned_start) {                     \
	                return true;                                    \
	        }                                                       \
                                                                        \
	        return false;                                           \
	}                                                               \
                                                                        \
	/* like range_overflows_allow_zero(), but without the */        \
	/* unconditional approval of size==0 */                         \
	__attribute__((overloadable, used))                             \
	static bool                                                     \
	range_overflows_strict_zero(T start, T size, T pgmask)                      \
	{                                                               \
	        T sum;                                                  \
	        if (__builtin_add_overflow(start, size, &sum)) {        \
	                return true;                                    \
	        }                                                       \
                                                                        \
	        T aligned_start = trunc_down_mask(start, pgmask);       \
	        T aligned_end = round_up_mask(start + size, pgmask);    \
	        if (aligned_end <= aligned_start) {                     \
	                return true;                                    \
	        }                                                       \
                                                                        \
	        return false;                                           \
	}                                                               \

IMPL(uint64_t)
IMPL(uint32_t)
#undef IMPL


// return true if the process is running under Rosetta translation
// https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment#Determine-Whether-Your-App-Is-Running-as-a-Translated-Binary
static bool
isRosetta()
{
#if KERNEL
	return false;
#else
	int out_value = 0;
	size_t io_size = sizeof(out_value);
	if (sysctlbyname("sysctl.proc_translated", &out_value, &io_size, NULL, 0) == 0) {
		assert(io_size >= sizeof(out_value));
		return out_value;
	}
	return false;
#endif
}

#if KERNEL
// Knobs controlled by boot arguments
extern bool kernel_generate_golden;
static void
init_kernel_generate_golden()
{
	kernel_generate_golden = FALSE;
	uint32_t kern_golden_arg;
	if (PE_parse_boot_argn("vm_parameter_validation_kern_golden", &kern_golden_arg, sizeof(kern_golden_arg))) {
		kernel_generate_golden = (kern_golden_arg == 1);
	}
}
#else
// Knobs controlled by environment variables
extern bool dump;
extern bool generate_golden;
extern bool test_results;
static void
read_env()
{
	dump = (getenv("DUMP_RESULTS") != NULL);
	generate_golden = (getenv("GENERATE_GOLDEN_IMAGE") != NULL);
	test_results = (getenv("SKIP_TESTS") == NULL) && !generate_golden; // Shouldn't do both
}
#endif


/////////////////////////////////////////////////////
// String functions that work in both kernel and userspace.

// Test output function.
// This prints either to stdout (userspace tests) or to a userspace buffer (kernel sysctl tests)
#if KERNEL
extern void testprintf(const char *, ...) __printflike(1, 2);
#else
#define testprintf printf
#endif

// kstrdup() is like strdup() but in the kernel it uses kalloc_data()
static inline char *
kstrdup(const char *str)
{
#if KERNEL
	size_t size = strlen(str) + 1;
	char *copy = kalloc_data(size, Z_WAITOK | Z_ZERO);
	memcpy(copy, str, size);
	return copy;
#else
	return strdup(str);
#endif
}

// kfree_str() is like free() but in the kernel it uses kfree_data_addr()
static inline void
kfree_str(char *str)
{
#if KERNEL
	kfree_data_addr(str);
#else
	free(str);
#endif
}

// kasprintf() is like asprintf() but in the kernel it uses kalloc_data()

#if !KERNEL
#       define kasprintf asprintf
#else
extern int vsnprintf(char *, size_t, const char *, va_list) __printflike(3, 0);
static inline int
kasprintf(char ** __restrict out_str, const char * __restrict format, ...) __printflike(2, 3)
{
	va_list args1, args2;

	// compute length
	char c;
	va_start(args1, format);
	va_copy(args2, args1);
	int len1 = vsnprintf(&c, sizeof(c), format, args1);
	va_end(args1);
	if (len1 < 0) {
		*out_str = NULL;
		return len1;
	}

	// allocate and print
	char *str = kalloc_data(len1 + 1, Z_NOFAIL);
	int len2 = vsnprintf(str, len1 + 1, format, args2);
	va_end(args2);
	if (len2 < 0) {
		kfree_data_addr(str);
		*out_str = NULL;
		return len1;
	}
	assert(len1 == len2);

	*out_str = str;
	return len1;
}
// KERNEL
#endif


/////////////////////////////////////////////////////
// Record trials and return values from tested functions (BSD int or Mach kern_return_t)

// ret: return value of this trial
// name: name of this trial, including the input values passed in
typedef struct {
	int ret;
	char *name;
} result_t;

typedef struct {
	const char *testname;
	char *testconfig;
	unsigned capacity;
	unsigned count;
	result_t list[];
} results_t;

extern results_t *golden_list[];
extern results_t *kern_list[];
static uint32_t num_tests = 0; // num of tests in golden list
static uint32_t num_kern_tests = 0; // num of tests in kernel results list

static __attribute__((overloadable))
results_t *
alloc_results(const char *testname, char *testconfig, unsigned capacity)
{
	results_t *results;
#if KERNEL
	results = kalloc_type(results_t, result_t, capacity, Z_WAITOK | Z_ZERO);
#else
	results = calloc(sizeof(results_t) + capacity * sizeof(result_t), 1);
#endif
	assert(results != NULL);
	results->testname = testname;
	results->testconfig = testconfig;
	results->capacity = capacity;
	results->count = 0;
	return results;
}

static char *
alloc_default_testconfig(void)
{
	char *result;
	kasprintf(&result, "%s %s %s%s",
	    OS_NAME, ARCH_NAME, CALLER_NAME, isRosetta() ? " rosetta" : "");
	return result;
}

static __attribute__((overloadable))
results_t *
alloc_results(const char *testname, unsigned capacity)
{
	return alloc_results(testname, alloc_default_testconfig(), capacity);
}

static void __unused
dealloc_results(results_t *results)
{
	for (unsigned int i = 0; i < results->count; i++) {
		kfree_str(results->list[i].name);
	}
	kfree_str(results->testconfig);
#if KERNEL
	kfree_type(results_t, result_t, results->capacity, results);
#else
	free(results);
#endif
}

static void __attribute__((overloadable, unused))
append_result(results_t *results, int ret, const char *name)
{
	// halt if the results list is already full
	// fixme reallocate instead if we can't always choose the size in advance
	assert(results->count < results->capacity);

	// name may be freed before we make use of it
	char * name_cpy = kstrdup(name);
	assert(name_cpy);
	results->list[results->count++] =
	    (result_t){.ret = ret, .name = name_cpy};
}

static results_t *
test_name_to_golden_results(const char* testname)
{
	results_t *golden_results = NULL;
	results_t *golden_results_found = NULL;

	for (uint32_t x = 0; x < num_tests; x++) {
		golden_results = golden_list[x];
		if (strncmp(golden_results->testname, testname, strlen(testname)) == 0) {
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

#define TESTNAME_DELIMITER        "TESTNAME "
#define RESULTCOUNT_DELIMITER     "RESULT COUNT "
#define TESTRESULT_DELIMITER      " "
#define TESTCONFIG_DELIMITER      "  TESTCONFIG "
#define KERN_TESTRESULT_DELIMITER "  RESULT "

// print results, unformatted
// This output is read by populate_kernel_results()
// and by tools/format_vm_parameter_validation.py
static results_t *
__dump_results(results_t *results)
{
	testprintf(TESTNAME_DELIMITER "%s\n", results->testname);
	testprintf(TESTCONFIG_DELIMITER "%s\n", results->testconfig);

	for (unsigned i = 0; i < results->count; i++) {
		testprintf(KERN_TESTRESULT_DELIMITER "%d, %s\n", results->list[i].ret, results->list[i].name);
	}

	return results;
}

// This output is read by populate_golden_results()
static results_t *
dump_golden_results(results_t *results)
{
	testprintf(TESTNAME_DELIMITER "%s\n", results->testname);
	testprintf(RESULTCOUNT_DELIMITER "%d\n", results->count);

	for (unsigned i = 0; i < results->count; i++) {
		testprintf(TESTRESULT_DELIMITER "%d: %d\n", i, results->list[i].ret);
	}

	return results;
}

#if !KERNEL
static void
do_tests(results_t *golden_results, results_t *results)
{
	bool passed = TRUE;
	unsigned result_count = golden_results->count;
	if (golden_results->count != results->count) {
		T_LOG("%s: number of iterations mismatch (%u vs %u)",
		    results->testname, golden_results->count, results->count);
		result_count = golden_results->count < results->count ? golden_results->count : results->count;
	}
	for (unsigned i = 0; i < result_count; i++) {
		if (results->list[i].ret == ACCEPTABLE) {
			// trial has declared itself to be correct
			// no matter what the golden result is
			T_LOG("%s RESULT ACCEPTABLE (expected %d), %s\n",
			    results->testname,
			    golden_results->list[i].ret, results->list[i].name);
		} else if (results->list[i].ret != golden_results->list[i].ret) {
			T_FAIL("%s RESULT %d (expected %d), %s\n",
			    results->testname, results->list[i].ret,
			    golden_results->list[i].ret, results->list[i].name);
			passed = FALSE;
		}
	}

	if (passed) {
		T_PASS("%s passed\n", results->testname);
	}
}
#endif

static results_t *
dump_results(results_t *results)
{
#if KERNEL
	if (kernel_generate_golden) {
		return dump_golden_results(results);
	} else {
		return __dump_results(results);
	}
#else
	results_t *golden_results = NULL;

	if (dump && !generate_golden) {
		__dump_results(results);
	}

	if (generate_golden) {
		dump_golden_results(results);
	}

	if (test_results) {
		golden_results = test_name_to_golden_results(results->testname);

		if (golden_results) {
			do_tests(golden_results, results);
		} else {
			T_FAIL("New test %s found, update golden list to allow return code testing", results->testname);
			// Dump results if not done previously
			if (!dump) {
				__dump_results(results);
			}
		}
	}

	return results;
#endif
}

static inline mach_vm_address_t
truncate_vm_map_addr_with_flags(MAP_T map, mach_vm_address_t addr, int flags)
{
	mach_vm_address_t truncated_addr = addr;
	if (flags & VM_FLAGS_RETURN_4K_DATA_ADDR) {
		// VM_FLAGS_RETURN_4K_DATA_ADDR means return a 4k aligned address rather than the
		// base of the page. Truncate to 4k.
		truncated_addr = trunc_down_page(addr, KB4);
	} else if (flags & VM_FLAGS_RETURN_DATA_ADDR) {
		// On VM_FLAGS_RETURN_DATA_ADDR, we expect to get back the unaligned address.
		// Don't truncate.
	} else {
		// Otherwise we truncate to the map page size
		truncated_addr = trunc_down_map(map, addr);
	}
	return truncated_addr;
}


static inline mach_vm_address_t
get_expected_remap_misalignment(MAP_T map, mach_vm_address_t addr, int flags)
{
	mach_vm_address_t misalignment;
	if (flags & VM_FLAGS_RETURN_4K_DATA_ADDR) {
		// VM_FLAGS_RETURN_4K_DATA_ADDR means return a 4k aligned address rather than the
		// base of the page. The misalignment is relative to the first 4k page
		misalignment = addr - trunc_down_page(addr, KB4);
	} else if (flags & VM_FLAGS_RETURN_DATA_ADDR) {
		// On VM_FLAGS_RETURN_DATA_ADDR, we expect to get back the unaligned address.
		// The misalignment is therefore the low bits
		misalignment = addr - trunc_down_map(map, addr);
	} else {
		// Otherwise we expect it to be aligned
		misalignment = 0;
	}
	return misalignment;
}

// absolute and relative offsets are used to specify a trial's values

typedef struct {
	bool is_absolute;
	addr_t offset;
} absolute_or_relative_offset_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	absolute_or_relative_offset_t list[];
} offset_list_t;

static offset_list_t *
allocate_offsets(unsigned capacity)
{
	offset_list_t *offsets;
#if KERNEL
	offsets = kalloc_type(offset_list_t, absolute_or_relative_offset_t, capacity, Z_WAITOK | Z_ZERO);
#else
	offsets = calloc(sizeof(offset_list_t) + capacity * sizeof(absolute_or_relative_offset_t), 1);
#endif
	offsets->count = 0;
	offsets->capacity = capacity;
	return offsets;
}

static void
append_offset(offset_list_t *offsets, bool is_absolute, addr_t offset)
{
	assert(offsets->count < offsets->capacity);
	offsets->list[offsets->count].is_absolute = is_absolute;
	offsets->list[offsets->count].offset = offset;
	offsets->count++;
}

static void
free_offsets(offset_list_t *offsets)
{
#if KERNEL
	kfree_type(offset_list_t, absolute_or_relative_offset_t, offsets->capacity, offsets);
#else
	free(offsets);
#endif
}


/////////////////////////////////////////////////////
// Generation of trials and their parameter values
// A "trial" is a single execution of a function to be tested

#if KERNEL
#define ALLOC_TRIALS(NAME, new_capacity)                                \
	(NAME ## _trials_t *)kalloc_type(NAME ## _trials_t, NAME ## _trial_t, \
	                                 new_capacity, Z_WAITOK | Z_ZERO)
#define FREE_TRIALS(NAME, trials)                                       \
	kfree_type(NAME ## _trials_t, NAME ## _trial_t, trials->capacity, trials)
#else
#define ALLOC_TRIALS(NAME, new_capacity)                                \
	(NAME ## _trials_t *)calloc(sizeof(NAME ## _trials_t) + (new_capacity) * sizeof(NAME ## _trial_t), 1)
#define FREE_TRIALS(NAME, trials)               \
	free(trials)
#endif

#define TRIALS_IMPL(NAME)                                               \
	static NAME ## _trials_t *                                      \
	allocate_ ## NAME ## _trials(unsigned capacity)                 \
	{                                                               \
	        NAME ## _trials_t *trials = ALLOC_TRIALS(NAME, capacity); \
	        assert(trials);                                         \
	        trials->count = 0;                                      \
	        trials->capacity = capacity;                            \
	        return trials;                                          \
	}                                                               \
                                                                        \
	static void __attribute__((overloadable, used))                 \
	free_trials(NAME ## _trials_t *trials)                          \
	{                                                               \
	        FREE_TRIALS(NAME, trials);                              \
	}                                                               \
                                                                        \
	static void __attribute__((overloadable, used))                 \
	append_trial(NAME ## _trials_t *trials, NAME ## _trial_t new_trial) \
	{                                                               \
	        assert(trials->count < trials->capacity);               \
	        trials->list[trials->count++] = new_trial;              \
	}                                                               \
                                                                        \
	static void __attribute__((overloadable, used))                 \
	append_trials(NAME ## _trials_t *trials, NAME ## _trial_t *new_trials, unsigned new_count) \
	{                                                               \
	        for (unsigned i = 0; i < new_count; i++) {              \
	                append_trial(trials, new_trials[i]);            \
	        }                                                       \
	}

// allocate vm_inherit_t trials, and deallocate it at end of scope
#define SMART_VM_INHERIT_TRIALS()                                               \
	__attribute__((cleanup(cleanup_vm_inherit_trials)))             \
	= allocate_vm_inherit_trials(countof(vm_inherit_trials_values));        \
	append_trials(trials, vm_inherit_trials_values, countof(vm_inherit_trials_values))

// generate vm_inherit_t trials

typedef struct {
	vm_inherit_t value;
	const char * name;
} vm_inherit_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	vm_inherit_trial_t list[];
} vm_inherit_trials_t;


#define VM_INHERIT_TRIAL(new_value) \
	(vm_inherit_trial_t) {.value = (vm_inherit_t)new_value, .name ="vm_inherit " #new_value}

static vm_inherit_trial_t vm_inherit_trials_values[] = {
	VM_INHERIT_TRIAL(VM_INHERIT_SHARE),
	VM_INHERIT_TRIAL(VM_INHERIT_COPY),
	VM_INHERIT_TRIAL(VM_INHERIT_NONE),
	// end valid ones
	VM_INHERIT_TRIAL(VM_INHERIT_DONATE_COPY), // yes this is invalid
	VM_INHERIT_TRIAL(0x12345),
	VM_INHERIT_TRIAL(0xffffffff),
};

TRIALS_IMPL(vm_inherit)

static void
cleanup_vm_inherit_trials(vm_inherit_trials_t **trials)
{
	free_trials(*trials);
}

// allocate vm_map_kernel_flags trials, and deallocate it at end of scope
#define SMART_VM_MAP_KERNEL_FLAGS_TRIALS()                              \
	__attribute__((cleanup(cleanup_vm_map_kernel_flags_trials)))    \
	= generate_vm_map_kernel_flags_trials()

#define SMART_MMAP_KERNEL_FLAGS_TRIALS()                                \
	__attribute__((cleanup(cleanup_vm_map_kernel_flags_trials)))    \
	= generate_mmap_kernel_flags_trials()

// generate vm_map_kernel_flags_t trials

typedef struct {
	int flags;
	char * name;
} vm_map_kernel_flags_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	vm_map_kernel_flags_trial_t list[];
} vm_map_kernel_flags_trials_t;

#define VM_MAP_KERNEL_FLAGS_TRIAL(new_flags) \
	(vm_map_kernel_flags_trial_t) {.flags = (int)(new_flags), .name ="vm_map_kernel_flags " #new_flags}

TRIALS_IMPL(vm_map_kernel_flags)

static vm_map_kernel_flags_trials_t *
generate_prefixed_vm_map_kernel_flags_trials(int prefix_flags, const char *prefix_name)
{
	vm_map_kernel_flags_trials_t *trials;
	trials = allocate_vm_map_kernel_flags_trials(32);

	char *str;
#define APPEND(flag)                                                    \
	({                                                              \
	        kasprintf(&str, "vm_map_kernel_flags %s%s%s", \
	            prefix_name, prefix_flags == 0 ? "" : " | ", #flag); \
	        append_trial(trials, (vm_map_kernel_flags_trial_t){ prefix_flags | (int)flag, str }); \
	})

	// First trial is just the prefix flags set, if any.
	// (either ANYWHERE or FIXED | OVERWRITE)
	if (prefix_flags != 0) {
		kasprintf(&str, "vm_map_kernel_flags %s", prefix_name);
		append_trial(trials, (vm_map_kernel_flags_trial_t){ prefix_flags, str });
	}

	// Try each other flag with the prefix flags.
	// Skip FIXED and ANYWHERE and OVERWRITE because they cause
	// memory management changes that the caller may not be prepared for.
	// skip 0x00000000 VM_FLAGS_FIXED
	// skip 0x00000001 VM_FLAGS_ANYWHERE
	APPEND(VM_FLAGS_PURGABLE);
	APPEND(VM_FLAGS_4GB_CHUNK);
	APPEND(VM_FLAGS_RANDOM_ADDR);
	APPEND(VM_FLAGS_NO_CACHE);
	APPEND(VM_FLAGS_RESILIENT_CODESIGN);
	APPEND(VM_FLAGS_RESILIENT_MEDIA);
	APPEND(VM_FLAGS_PERMANENT);
	// skip 0x00001000 VM_FLAGS_TPRO; it only works on some hardware.
	APPEND(0x00002000);
	// skip 0x00004000 VM_FLAGS_OVERWRITE
	APPEND(0x00008000);
	APPEND(VM_FLAGS_SUPERPAGE_MASK); // 0x10000, 0x20000, 0x40000
	APPEND(0x00080000);
	APPEND(VM_FLAGS_RETURN_DATA_ADDR);
	APPEND(VM_FLAGS_RETURN_4K_DATA_ADDR);
	APPEND(VM_FLAGS_ALIAS_MASK);

	return trials;
}

static vm_map_kernel_flags_trials_t *
generate_vm_map_kernel_flags_trials()
{
	vm_map_kernel_flags_trials_t *fixed =
	    generate_prefixed_vm_map_kernel_flags_trials(
		VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, "VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE");
	vm_map_kernel_flags_trials_t *anywhere =
	    generate_prefixed_vm_map_kernel_flags_trials(
		VM_FLAGS_ANYWHERE, "VM_FLAGS_ANYWHERE");
	vm_map_kernel_flags_trials_t *trials =
	    allocate_vm_map_kernel_flags_trials(fixed->count + anywhere->count);
	append_trials(trials, fixed->list, fixed->count);
	append_trials(trials, anywhere->list, anywhere->count);

	// free not cleanup, trials has stolen their strings
	free_trials(fixed);
	free_trials(anywhere);

	return trials;
}

static vm_map_kernel_flags_trials_t *
generate_mmap_kernel_flags_trials()
{
	// mmap rejects both ANYWHERE and FIXED | OVERWRITE
	// so don't set any prefix flags.
	return generate_prefixed_vm_map_kernel_flags_trials(0, "");
}

static void
cleanup_vm_map_kernel_flags_trials(vm_map_kernel_flags_trials_t **trials)
{
	for (size_t i = 0; i < (*trials)->count; i++) {
		kfree_str((*trials)->list[i].name);
	}
	free_trials(*trials);
}


// generate mmap flags trials

typedef struct {
	int flags;
	const char *name;
} mmap_flags_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	mmap_flags_trial_t list[];
} mmap_flags_trials_t;

#define MMAP_FLAGS_TRIAL(new_flags)                                             \
	(mmap_flags_trial_t){ .flags = (int)(new_flags), .name = "mmap flags "#new_flags }

static mmap_flags_trial_t mmap_flags_trials_values[] = {
	MMAP_FLAGS_TRIAL(MAP_FILE),
	MMAP_FLAGS_TRIAL(MAP_ANON),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_SHARED),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE),
	MMAP_FLAGS_TRIAL(MAP_ANON | MAP_SHARED),
	MMAP_FLAGS_TRIAL(MAP_ANON | MAP_PRIVATE),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_SHARED | MAP_PRIVATE),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | MAP_FIXED),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | MAP_RENAME),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | MAP_NORESERVE),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | MAP_RESERVED0080),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | MAP_NOEXTEND),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | MAP_HASSEMAPHORE),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | MAP_NOCACHE),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | MAP_JIT),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | MAP_RESILIENT_CODESIGN),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | MAP_RESILIENT_MEDIA),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | MAP_TRANSLATED_ALLOW_EXECUTE),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | MAP_UNIX03),
	// skip MAP_TPRO; it only works on some hardware
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 3),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 4),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 5),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 6),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 7),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 8),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 9),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 10),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 11),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 12),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 13),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 14),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 15),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 16),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 17),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 18),
	// skip MAP_TPRO (1<<19); it only works on some hardware
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 20),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 21),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 22),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 23),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 24),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 25),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 26),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 27),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 28),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 29),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 30),
	MMAP_FLAGS_TRIAL(MAP_FILE | MAP_PRIVATE | 1u << 31),
};

TRIALS_IMPL(mmap_flags)

static void
cleanup_mmap_flags_trials(mmap_flags_trials_t **trials)
{
	free_trials(*trials);
}

// allocate mmap_flag trials, and deallocate it at end of scope
#define SMART_MMAP_FLAGS_TRIALS()                                               \
	__attribute__((cleanup(cleanup_mmap_flags_trials)))             \
	= allocate_mmap_flags_trials(countof(mmap_flags_trials_values));        \
	append_trials(trials, mmap_flags_trials_values, countof(mmap_flags_trials_values))

// generate generic flag trials

typedef struct {
	int flag;
	const char *name;
} generic_flag_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	generic_flag_trial_t list[];
} generic_flag_trials_t;

#define GENERIC_FLAG_TRIAL(new_flag)                                            \
	(generic_flag_trial_t){ .flag = (int)(new_flag), .name = "generic flag "#new_flag }

static generic_flag_trial_t generic_flag_trials_values[] = {
	GENERIC_FLAG_TRIAL(0),
	GENERIC_FLAG_TRIAL(1),
	GENERIC_FLAG_TRIAL(2),
	GENERIC_FLAG_TRIAL(3),
	GENERIC_FLAG_TRIAL(4),
	GENERIC_FLAG_TRIAL(5),
	GENERIC_FLAG_TRIAL(6),
	GENERIC_FLAG_TRIAL(7),
	GENERIC_FLAG_TRIAL(1u << 3),
	GENERIC_FLAG_TRIAL(1u << 4),
	GENERIC_FLAG_TRIAL(1u << 5),
	GENERIC_FLAG_TRIAL(1u << 6),
	GENERIC_FLAG_TRIAL(1u << 7),
	GENERIC_FLAG_TRIAL(1u << 8),
	GENERIC_FLAG_TRIAL(1u << 9),
	GENERIC_FLAG_TRIAL(1u << 10),
	GENERIC_FLAG_TRIAL(1u << 11),
	GENERIC_FLAG_TRIAL(1u << 12),
	GENERIC_FLAG_TRIAL(1u << 13),
	GENERIC_FLAG_TRIAL(1u << 14),
	GENERIC_FLAG_TRIAL(1u << 15),
	GENERIC_FLAG_TRIAL(1u << 16),
	GENERIC_FLAG_TRIAL(1u << 17),
	GENERIC_FLAG_TRIAL(1u << 18),
	GENERIC_FLAG_TRIAL(1u << 19),
	GENERIC_FLAG_TRIAL(1u << 20),
	GENERIC_FLAG_TRIAL(1u << 21),
	GENERIC_FLAG_TRIAL(1u << 22),
	GENERIC_FLAG_TRIAL(1u << 23),
	GENERIC_FLAG_TRIAL(1u << 24),
	GENERIC_FLAG_TRIAL(1u << 25),
	GENERIC_FLAG_TRIAL(1u << 26),
	GENERIC_FLAG_TRIAL(1u << 27),
	GENERIC_FLAG_TRIAL(1u << 28),
	GENERIC_FLAG_TRIAL(1u << 29),
	GENERIC_FLAG_TRIAL(1u << 30),
	GENERIC_FLAG_TRIAL(1u << 31),
};

TRIALS_IMPL(generic_flag)

static void
cleanup_generic_flag_trials(generic_flag_trials_t **trials)
{
	free_trials(*trials);
}

// allocate mmap_flag trials, and deallocate it at end of scope
#define SMART_GENERIC_FLAG_TRIALS()                                             \
	__attribute__((cleanup(cleanup_generic_flag_trials)))           \
	= allocate_generic_flag_trials(countof(generic_flag_trials_values));    \
	append_trials(trials, generic_flag_trials_values, countof(generic_flag_trials_values))


// generate vm_prot_t trials

#ifndef KERNEL
typedef int vm_tag_t;
#endif /* KERNEL */

typedef struct {
	vm_tag_t tag;
	const char *name;
} vm_tag_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	vm_tag_trial_t list[];
} vm_tag_trials_t;

#define VM_TAG_TRIAL(new_tag)                                           \
	(vm_tag_trial_t){ .tag = (vm_tag_t)(new_tag), .name = "vm_tag "#new_tag }

static vm_tag_trial_t vm_tag_trials_values[] = {
	#ifdef KERNEL
	VM_TAG_TRIAL(VM_KERN_MEMORY_NONE),
	VM_TAG_TRIAL(VM_KERN_MEMORY_OSFMK),
	VM_TAG_TRIAL(VM_KERN_MEMORY_BSD),
	VM_TAG_TRIAL(VM_KERN_MEMORY_IOKIT),
	VM_TAG_TRIAL(VM_KERN_MEMORY_LIBKERN),
	VM_TAG_TRIAL(VM_KERN_MEMORY_OSKEXT),
	VM_TAG_TRIAL(VM_KERN_MEMORY_KEXT),
	VM_TAG_TRIAL(VM_KERN_MEMORY_IPC),
	VM_TAG_TRIAL(VM_KERN_MEMORY_STACK),
	VM_TAG_TRIAL(VM_KERN_MEMORY_CPU),
	VM_TAG_TRIAL(VM_KERN_MEMORY_PMAP),
	VM_TAG_TRIAL(VM_KERN_MEMORY_PTE),
	VM_TAG_TRIAL(VM_KERN_MEMORY_ZONE),
	VM_TAG_TRIAL(VM_KERN_MEMORY_KALLOC),
	VM_TAG_TRIAL(VM_KERN_MEMORY_COMPRESSOR),
	VM_TAG_TRIAL(VM_KERN_MEMORY_COMPRESSED_DATA),
	VM_TAG_TRIAL(VM_KERN_MEMORY_PHANTOM_CACHE),
	VM_TAG_TRIAL(VM_KERN_MEMORY_WAITQ),
	VM_TAG_TRIAL(VM_KERN_MEMORY_DIAG),
	VM_TAG_TRIAL(VM_KERN_MEMORY_LOG),
	VM_TAG_TRIAL(VM_KERN_MEMORY_FILE),
	VM_TAG_TRIAL(VM_KERN_MEMORY_MBUF),
	VM_TAG_TRIAL(VM_KERN_MEMORY_UBC),
	VM_TAG_TRIAL(VM_KERN_MEMORY_SECURITY),
	VM_TAG_TRIAL(VM_KERN_MEMORY_MLOCK),
	VM_TAG_TRIAL(VM_KERN_MEMORY_REASON),
	VM_TAG_TRIAL(VM_KERN_MEMORY_SKYWALK),
	VM_TAG_TRIAL(VM_KERN_MEMORY_LTABLE),
	VM_TAG_TRIAL(VM_KERN_MEMORY_HV),
	VM_TAG_TRIAL(VM_KERN_MEMORY_KALLOC_DATA),
	VM_TAG_TRIAL(VM_KERN_MEMORY_RETIRED),
	VM_TAG_TRIAL(VM_KERN_MEMORY_KALLOC_TYPE),
	VM_TAG_TRIAL(VM_KERN_MEMORY_TRIAGE),
	VM_TAG_TRIAL(VM_KERN_MEMORY_RECOUNT),
	#endif /* KERNEL */
};

TRIALS_IMPL(vm_tag)

static void
cleanup_vm_tag_trials(vm_tag_trials_t **trials)
{
	free_trials(*trials);
}

#define SMART_VM_TAG_TRIALS()                                           \
	__attribute__((cleanup(cleanup_vm_tag_trials)))         \
	= allocate_vm_tag_trials(countof(vm_tag_trials_values));        \
	append_trials(trials, vm_tag_trials_values, countof(vm_tag_trials_values))

//END vm_tag_t

// generate vm_prot_t trials

typedef struct {
	vm_prot_t prot;
	const char *name;
} vm_prot_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	vm_prot_trial_t list[];
} vm_prot_trials_t;

#define VM_PROT_TRIAL(new_prot)                                         \
	(vm_prot_trial_t){ .prot = (vm_prot_t)(new_prot), .name = "vm_prot "#new_prot }

static vm_prot_trial_t vm_prot_trials_values[] = {
	// none
	VM_PROT_TRIAL(VM_PROT_NONE),
	// ordinary r-- / rw- / r-x
	VM_PROT_TRIAL(VM_PROT_READ),
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_WRITE),
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_EXECUTE),
	// rwx (w+x often disallowed)
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE),
	// VM_PROT_READ | VM_PROT_x for each other VM_PROT_x bit
	// plus write and execute for some interesting cases
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 3),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 4),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 5),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 6),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 7),
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_WRITE | 1u << 7),
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_EXECUTE | 1u << 7),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 8),
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_WRITE | 1u << 8),
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_EXECUTE | 1u << 8),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 9),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 10),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 11),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 12),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 13),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 14),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 15),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 16),
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_WRITE | 1u << 16),
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_EXECUTE | 1u << 16),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 17),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 18),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 19),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 20),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 21),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 22),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 23),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 24),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 25),
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_WRITE | 1u << 25),
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_EXECUTE | 1u << 25),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 26),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 27),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 28),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 29),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 30),
	VM_PROT_TRIAL(VM_PROT_READ | 1u << 31),
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_WRITE | 1u << 31),
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_EXECUTE | 1u << 31),
};

TRIALS_IMPL(vm_prot)

static void
cleanup_vm_prot_trials(vm_prot_trials_t **trials)
{
	free_trials(*trials);
}

// allocate vm_prot trials, and deallocate it at end of scope
#define SMART_VM_PROT_TRIALS()                                          \
	__attribute__((cleanup(cleanup_vm_prot_trials)))                \
	= allocate_vm_prot_trials(countof(vm_prot_trials_values));      \
	append_trials(trials, vm_prot_trials_values, countof(vm_prot_trials_values))

// Trials for pairs of vm_prot_t

typedef struct {
	vm_prot_t cur;
	vm_prot_t max;
	char * name;
} vm_prot_pair_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	vm_prot_pair_trial_t list[];
} vm_prot_pair_trials_t;

TRIALS_IMPL(vm_prot_pair)

#define VM_PROT_PAIR_TRIAL(new_cur, new_max, new_name) \
(vm_prot_pair_trial_t){ .cur = (vm_prot_t)(new_cur), \
	        .max = (vm_prot_t)(new_max), \
	        .name = new_name,}

vm_prot_pair_trials_t *
generate_vm_prot_pair_trials()
{
	const unsigned D = countof(vm_prot_trials_values);
	unsigned num_trials = D * D;

	vm_prot_pair_trials_t * trials = allocate_vm_prot_pair_trials(num_trials);
	for (size_t i = 0; i < D; i++) {
		for (size_t j = 0; j < D; j++) {
			vm_prot_t cur = vm_prot_trials_values[i].prot;
			vm_prot_t max = vm_prot_trials_values[j].prot;
			char *str;
			kasprintf(&str, "cur: 0x%x, max: 0x%x", cur, max);
			append_trial(trials, VM_PROT_PAIR_TRIAL(cur, max, str));
		}
	}
	return trials;
}

#define SMART_VM_PROT_PAIR_TRIALS()                                             \
	__attribute__((cleanup(cleanup_vm_prot_pair_trials)))           \
	= generate_vm_prot_pair_trials();

static void
cleanup_vm_prot_pair_trials(vm_prot_pair_trials_t **trials)
{
	for (size_t i = 0; i < (*trials)->count; i++) {
		kfree_str((*trials)->list[i].name);
	}
	free_trials(*trials);
}

// generate ledger tag trials

typedef struct {
	int tag;
	const char *name;
} ledger_tag_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	ledger_tag_trial_t list[];
} ledger_tag_trials_t;

#define LEDGER_TAG_TRIAL(new_tag)                            \
	(ledger_tag_trial_t){ .tag = (int)(new_tag), .name = "ledger tag "#new_tag }

static ledger_tag_trial_t ledger_tag_trials_values[] = {
	LEDGER_TAG_TRIAL(VM_LEDGER_TAG_NONE),
	LEDGER_TAG_TRIAL(VM_LEDGER_TAG_DEFAULT),
	LEDGER_TAG_TRIAL(VM_LEDGER_TAG_NETWORK),
	LEDGER_TAG_TRIAL(VM_LEDGER_TAG_MEDIA),
	LEDGER_TAG_TRIAL(VM_LEDGER_TAG_GRAPHICS),
	LEDGER_TAG_TRIAL(VM_LEDGER_TAG_NEURAL),
	LEDGER_TAG_TRIAL(VM_LEDGER_TAG_MAX),
	LEDGER_TAG_TRIAL(1u << 16),
	LEDGER_TAG_TRIAL(1u << 17),
	LEDGER_TAG_TRIAL(1u << 18),
	LEDGER_TAG_TRIAL(1u << 19),
	LEDGER_TAG_TRIAL(1u << 20),
	LEDGER_TAG_TRIAL(1u << 21),
	LEDGER_TAG_TRIAL(1u << 22),
	LEDGER_TAG_TRIAL(1u << 23),
	LEDGER_TAG_TRIAL(1u << 24),
	LEDGER_TAG_TRIAL(1u << 25),
	LEDGER_TAG_TRIAL(1u << 26),
	LEDGER_TAG_TRIAL(1u << 27),
	LEDGER_TAG_TRIAL(1u << 28),
	LEDGER_TAG_TRIAL(1u << 29),
	LEDGER_TAG_TRIAL(1u << 30),
	LEDGER_TAG_TRIAL(1u << 31),
	LEDGER_TAG_TRIAL(VM_LEDGER_TAG_UNCHANGED),
};

TRIALS_IMPL(ledger_tag)

static void
cleanup_ledger_tag_trials(ledger_tag_trials_t **trials)
{
	free_trials(*trials);
}

// allocate ledger tag trials, and deallocate it at end of scope
#define SMART_LEDGER_TAG_TRIALS()                                               \
	__attribute__((cleanup(cleanup_ledger_tag_trials)))             \
	= allocate_ledger_tag_trials(countof(ledger_tag_trials_values));        \
	append_trials(trials, ledger_tag_trials_values, countof(ledger_tag_trials_values))


// generate ledger flag trials

typedef struct {
	int flag;
	const char *name;
} ledger_flag_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	ledger_flag_trial_t list[];
} ledger_flag_trials_t;

#define LEDGER_FLAG_TRIAL(new_flag)                            \
	(ledger_flag_trial_t){ .flag = (int)(new_flag), .name = "ledger flag "#new_flag }

static ledger_flag_trial_t ledger_flag_trials_values[] = {
	LEDGER_FLAG_TRIAL(0),
	LEDGER_FLAG_TRIAL(VM_LEDGER_FLAG_NO_FOOTPRINT),
	LEDGER_FLAG_TRIAL(VM_LEDGER_FLAG_NO_FOOTPRINT_FOR_DEBUG),
	LEDGER_FLAG_TRIAL(VM_LEDGER_FLAGS_USER),
	LEDGER_FLAG_TRIAL(VM_LEDGER_FLAG_FROM_KERNEL),
	LEDGER_FLAG_TRIAL(VM_LEDGER_FLAGS_ALL),
	LEDGER_FLAG_TRIAL(1u << 3),
	LEDGER_FLAG_TRIAL(1u << 4),
	LEDGER_FLAG_TRIAL(1u << 5),
	LEDGER_FLAG_TRIAL(1u << 6),
	LEDGER_FLAG_TRIAL(1u << 7),
	LEDGER_FLAG_TRIAL(1u << 8),
	LEDGER_FLAG_TRIAL(1u << 9),
	LEDGER_FLAG_TRIAL(1u << 10),
	LEDGER_FLAG_TRIAL(1u << 11),
	LEDGER_FLAG_TRIAL(1u << 12),
	LEDGER_FLAG_TRIAL(1u << 13),
	LEDGER_FLAG_TRIAL(1u << 14),
	LEDGER_FLAG_TRIAL(1u << 15),
	LEDGER_FLAG_TRIAL(1u << 16),
	LEDGER_FLAG_TRIAL(1u << 17),
	LEDGER_FLAG_TRIAL(1u << 18),
	LEDGER_FLAG_TRIAL(1u << 19),
	LEDGER_FLAG_TRIAL(1u << 20),
	LEDGER_FLAG_TRIAL(1u << 21),
	LEDGER_FLAG_TRIAL(1u << 22),
	LEDGER_FLAG_TRIAL(1u << 23),
	LEDGER_FLAG_TRIAL(1u << 24),
	LEDGER_FLAG_TRIAL(1u << 25),
	LEDGER_FLAG_TRIAL(1u << 26),
	LEDGER_FLAG_TRIAL(1u << 27),
	LEDGER_FLAG_TRIAL(1u << 28),
	LEDGER_FLAG_TRIAL(1u << 29),
	LEDGER_FLAG_TRIAL(1u << 30),
	LEDGER_FLAG_TRIAL(1u << 31),
};

TRIALS_IMPL(ledger_flag)

static void
cleanup_ledger_flag_trials(ledger_flag_trials_t **trials)
{
	free_trials(*trials);
}

// allocate ledger flag trials, and deallocate it at end of scope
#define SMART_LEDGER_FLAG_TRIALS()                                              \
	__attribute__((cleanup(cleanup_ledger_flag_trials)))            \
	= allocate_ledger_flag_trials(countof(ledger_flag_trials_values));      \
	append_trials(trials, ledger_flag_trials_values, countof(ledger_flag_trials_values))

// generate address-parameter trials
// where the address has no associated size
// and the callee's arithmetic includes `round_page(addr)`

typedef struct {
	addr_t addr;
	bool addr_is_absolute;
	char *name;
} addr_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	addr_trial_t list[];
} addr_trials_t;

#define ADDR_TRIAL(new_addr, new_absolute, new_name)                    \
	(addr_trial_t){ .addr = (addr_t)(new_addr), .addr_is_absolute = new_absolute, .name = new_name }

static addr_trial_t __attribute__((overloadable, used))
slide_trial(addr_trial_t trial, mach_vm_address_t slide)
{
	addr_trial_t result = trial;
	if (!trial.addr_is_absolute) {
		result.addr += slide;
	}
	return result;
}

static const offset_list_t *
get_addr_trial_offsets(void)
{
	static offset_list_t *offsets;
	if (!offsets) {
		offsets = allocate_offsets(20);
		append_offset(offsets, true, 0);
		append_offset(offsets, true, 1);
		append_offset(offsets, true, 2);
		append_offset(offsets, true, PAGE_SIZE - 2);
		append_offset(offsets, true, PAGE_SIZE - 1);
		append_offset(offsets, true, PAGE_SIZE);
		append_offset(offsets, true, PAGE_SIZE + 1);
		append_offset(offsets, true, PAGE_SIZE + 2);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE - 2);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE - 1);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE + 1);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE + 2);
		append_offset(offsets, true, -(mach_vm_address_t)2);
		append_offset(offsets, true, -(mach_vm_address_t)1);

		append_offset(offsets, false, 0);
		append_offset(offsets, false, 1);
		append_offset(offsets, false, 2);
		append_offset(offsets, false, PAGE_SIZE - 2);
		append_offset(offsets, false, PAGE_SIZE - 1);
	}
	return offsets;
}

TRIALS_IMPL(addr)

addr_trials_t *
generate_addr_trials(addr_t base)
{
	const offset_list_t *offsets = get_addr_trial_offsets();
	const unsigned ADDRS = offsets->count;
	addr_trials_t *trials = allocate_addr_trials(ADDRS);

	for (unsigned a = 0; a < ADDRS; a++) {
		mach_vm_address_t addr_offset = offsets->list[a].offset;
		mach_vm_address_t addr = addr_offset;
		bool addr_is_absolute = offsets->list[a].is_absolute;
		if (!addr_is_absolute) {
			addr += base;
		}

		char *str;
		kasprintf(&str, "addr: %s0x%llx",
		    addr_is_absolute ? "" : "base+", addr_offset);
		append_trial(trials, ADDR_TRIAL(addr, addr_is_absolute, str));
	}
	return trials;
}

static void
cleanup_addr_trials(addr_trials_t **trials)
{
	for (size_t i = 0; i < (*trials)->count; i++) {
		kfree_str((*trials)->list[i].name);
	}
	free_trials(*trials);
}

// allocate address trials around a base address
// and deallocate it at end of scope
#define SMART_ADDR_TRIALS(base)                                         \
	__attribute__((cleanup(cleanup_addr_trials)))                   \
	    = generate_addr_trials(base)


/////////////////////////////////////////////////////
// generate size-parameter trials
// where the size is not associated with any base address
// and the callee's arithmetic includes `round_page(size)`

typedef struct {
	addr_t size;
	char *name;
} size_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	size_trial_t list[];
} size_trials_t;

#define SIZE_TRIAL(new_size, new_name)                                          \
	(size_trial_t){ .size = (addr_t)(new_size), .name = new_name }

static const offset_list_t *
get_size_trial_offsets(void)
{
	static offset_list_t *offsets;
	if (!offsets) {
		offsets = allocate_offsets(15);
		append_offset(offsets, true, 0);
		append_offset(offsets, true, 1);
		append_offset(offsets, true, 2);
		append_offset(offsets, true, PAGE_SIZE - 2);
		append_offset(offsets, true, PAGE_SIZE - 1);
		append_offset(offsets, true, PAGE_SIZE);
		append_offset(offsets, true, PAGE_SIZE + 1);
		append_offset(offsets, true, PAGE_SIZE + 2);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE - 2);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE - 1);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE + 1);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE + 2);
		append_offset(offsets, true, -(mach_vm_address_t)2);
		append_offset(offsets, true, -(mach_vm_address_t)1);
	}
	return offsets;
}

TRIALS_IMPL(size)

size_trials_t *
generate_size_trials(void)
{
	const offset_list_t *size_offsets = get_size_trial_offsets();
	const unsigned SIZES = size_offsets->count;
	size_trials_t *trials = allocate_size_trials(SIZES);

	for (unsigned s = 0; s < SIZES; s++) {
		mach_vm_size_t size = size_offsets->list[s].offset;

		char *str;
		kasprintf(&str, "size: 0x%llx", size);
		append_trial(trials, SIZE_TRIAL(size, str));
	}
	return trials;
}

static void
cleanup_size_trials(size_trials_t **trials)
{
	for (size_t i = 0; i < (*trials)->count; i++) {
		kfree_str((*trials)->list[i].name);
	}
	free_trials(*trials);
}

// allocate size trials, and deallocate it at end of scope
#define SMART_SIZE_TRIALS()                                             \
	__attribute__((cleanup(cleanup_size_trials)))                   \
	= generate_size_trials()

/////////////////////////////////////////////////////
// generate start/size trials
// using absolute addresses or addresses around a given address
// where `size` is the size of the thing at `start`
// and the callee's arithmetic performs `start+size`

typedef struct {
	addr_t start;
	addr_t size;
	char *name;
	bool start_is_absolute;  // start computation does not include any allocation's base address
	bool size_is_absolute;   // size computation does not include start
} start_size_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	start_size_trial_t list[];
} start_size_trials_t;


#define START_SIZE_TRIAL(new_start, start_absolute, new_size, size_absolute, new_name) \
	(start_size_trial_t){ .start = (addr_t)(new_start), .size = (addr_t)(new_size), \
	                .name = new_name,                                       \
	                .start_is_absolute = start_absolute, .size_is_absolute = size_absolute }

static const offset_list_t *
get_start_size_trial_start_offsets(void)
{
	return get_addr_trial_offsets();
}

static const offset_list_t *
get_start_size_trial_size_offsets(void)
{
	static offset_list_t *offsets;
	if (!offsets) {
		// use each size offset twice: once absolute and once relative
		const offset_list_t *old_offsets = get_size_trial_offsets();
		offsets = allocate_offsets(2 * old_offsets->count);
		for (unsigned i = 0; i < old_offsets->count; i++) {
			append_offset(offsets, true, old_offsets->list[i].offset);
		}
		for (unsigned i = 0; i < old_offsets->count; i++) {
			append_offset(offsets, false, old_offsets->list[i].offset);
		}
	}
	return offsets;
}

TRIALS_IMPL(start_size)

// Return a new start/size trial which is offset by `slide` bytes
// Only "relative" start and size values get slid.
// "absolute" values don't change.
static start_size_trial_t __attribute__((overloadable, used))
slide_trial(start_size_trial_t trial, mach_vm_address_t slide)
{
	start_size_trial_t result = trial;
	if (!result.start_is_absolute) {
		result.start += slide;
		if (!result.size_is_absolute) {
			result.size -= slide;
		}
	}
	return result;
}

start_size_trials_t *
generate_start_size_trials(addr_t base)
{
	const offset_list_t *start_offsets = get_start_size_trial_start_offsets();
	const offset_list_t *size_offsets = get_start_size_trial_size_offsets();

	const unsigned ADDRS = start_offsets->count;
	const unsigned SIZES = size_offsets->count;

	start_size_trials_t *trials = allocate_start_size_trials(ADDRS * SIZES);

	for (unsigned a = 0; a < ADDRS; a++) {
		for (unsigned s = 0; s < SIZES; s++) {
			mach_vm_address_t start_offset = start_offsets->list[a].offset;
			mach_vm_address_t start = start_offset;
			bool start_is_absolute = start_offsets->list[a].is_absolute;
			if (!start_is_absolute) {
				start += base;
			}

			mach_vm_size_t size_offset = size_offsets->list[s].offset;
			mach_vm_size_t size = size_offset;
			bool size_is_absolute = size_offsets->list[s].is_absolute;
			if (!size_is_absolute) {
				size = -start + size;
			}

			char *str;
			kasprintf(&str, "start: %s0x%llx, size: %s0x%llx",
			    start_is_absolute ? "" : "base+", start_offset,
			    size_is_absolute ? "" :"-start+", size_offset);
			append_trial(trials, START_SIZE_TRIAL(start, start_is_absolute, size, size_is_absolute, str));
		}
	}
	return trials;
}

static void
cleanup_start_size_trials(start_size_trials_t **trials)
{
	for (size_t i = 0; i < (*trials)->count; i++) {
		kfree_str((*trials)->list[i].name);
	}
	free_trials(*trials);
}

// allocate start/size trials around a base address
// and deallocate it at end of scope
#define SMART_START_SIZE_TRIALS(base)                                   \
	__attribute__((cleanup(cleanup_start_size_trials)))             \
	= generate_start_size_trials(base)

// Trials for start/size/offset/object tuples

typedef struct {
	mach_vm_address_t start;
	mach_vm_size_t size;
	vm_object_offset_t offset;
	mach_vm_size_t obj_size;
	bool start_is_absolute;
	bool size_is_absolute;
	char * name;
} start_size_offset_object_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	start_size_offset_object_trial_t list[];
} start_size_offset_object_trials_t;

TRIALS_IMPL(start_size_offset_object)

#define START_SIZE_OFFSET_OBJECT_TRIAL(new_start, new_size, new_offset, new_obj_size, new_start_is_absolute, new_size_is_absolute, new_name) \
(start_size_offset_object_trial_t){ .start = (mach_vm_address_t)(new_start), \
	        .size = (mach_vm_size_t)(new_size), \
	        .offset = (vm_object_offset_t)(new_offset), \
	        .obj_size = (mach_vm_size_t)(new_obj_size), \
	        .start_is_absolute = (bool)(new_start_is_absolute), \
	        .size_is_absolute = (bool)(new_size_is_absolute), \
	        .name = new_name,}

bool
obj_size_is_ok(mach_vm_size_t obj_size)
{
	if (round_up_page(obj_size, PAGE_SIZE) == 0) {
		return false;
	}
	/* in rosetta, PAGE_SIZE is 4K but rounding to 16K also panics */ \
	if (isRosetta() && round_up_page(obj_size, KB16) == 0) {
		return false;
	}
	return true;
}

static start_size_offset_object_trial_t __attribute__((overloadable, used))
slide_trial(start_size_offset_object_trial_t trial, mach_vm_address_t slide)
{
	start_size_offset_object_trial_t result = trial;

	if (!trial.start_is_absolute) {
		result.start += slide;
		if (!trial.size_is_absolute) {
			result.size -= slide;
		}
	}
	return result;
}

static offset_list_t *
get_ssoo_absolute_offsets()
{
	static offset_list_t *offsets;
	if (!offsets) {
		offsets = allocate_offsets(20);
		append_offset(offsets, true, 0);
		append_offset(offsets, true, 1);
		append_offset(offsets, true, 2);
		append_offset(offsets, true, PAGE_SIZE - 2);
		append_offset(offsets, true, PAGE_SIZE - 1);
		append_offset(offsets, true, PAGE_SIZE);
		append_offset(offsets, true, PAGE_SIZE + 1);
		append_offset(offsets, true, PAGE_SIZE + 2);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE - 2);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE - 1);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE + 1);
		append_offset(offsets, true, -(mach_vm_address_t)PAGE_SIZE + 2);
		append_offset(offsets, true, -(mach_vm_address_t)2);
		append_offset(offsets, true, -(mach_vm_address_t)1);
	}
	return offsets;
}

static offset_list_t *
get_ssoo_absolute_and_relative_offsets()
{
	static offset_list_t *offsets;
	if (!offsets) {
		const offset_list_t *old_offsets = get_ssoo_absolute_offsets();
		offsets = allocate_offsets(old_offsets->count + 5);
		// absolute offsets
		for (unsigned i = 0; i < old_offsets->count; i++) {
			append_offset(offsets, true, old_offsets->list[i].offset);
		}
		// relative offsets
		append_offset(offsets, false, 0);
		append_offset(offsets, false, 1);
		append_offset(offsets, false, 2);
		append_offset(offsets, false, PAGE_SIZE - 2);
		append_offset(offsets, false, PAGE_SIZE - 1);
	}
	return offsets;
}

start_size_offset_object_trials_t *
generate_start_size_offset_object_trials()
{
	const offset_list_t *start_offsets = get_ssoo_absolute_and_relative_offsets();
	const offset_list_t *size_offsets  = get_ssoo_absolute_and_relative_offsets();
	const offset_list_t *offset_values = get_ssoo_absolute_offsets();
	const offset_list_t *object_sizes  = get_ssoo_absolute_offsets();

	unsigned num_trials = 0;
	for (size_t d = 0; d < object_sizes->count; d++) {
		mach_vm_size_t obj_size = object_sizes->list[d].offset;
		if (!obj_size_is_ok(obj_size)) { // make_a_mem_object would fail
			continue;
		}
		num_trials++;
	}
	num_trials *= start_offsets->count * size_offsets->count * offset_values->count;

	start_size_offset_object_trials_t * trials = allocate_start_size_offset_object_trials(num_trials);
	for (size_t a = 0; a < start_offsets->count; a++) {
		for (size_t b = 0; b < size_offsets->count; b++) {
			for (size_t c = 0; c < offset_values->count; c++) {
				for (size_t d = 0; d < object_sizes->count; d++) {
					bool start_is_absolute = start_offsets->list[a].is_absolute;
					bool size_is_absolute = size_offsets->list[b].is_absolute;
					mach_vm_address_t start = start_offsets->list[a].offset;
					mach_vm_size_t size = size_offsets->list[b].offset;
					vm_object_offset_t offset = offset_values->list[c].offset;
					mach_vm_size_t obj_size = object_sizes->list[d].offset;
					if (!obj_size_is_ok(obj_size)) { // make_a_mem_object would fail
						continue;
					}
					char *str;
					kasprintf(&str, "start: %s0x%llx, size: %s0x%llx, offset: 0x%llx, obj_size: 0x%llx",
					    start_is_absolute ? "" : "base+", start,
					    size_is_absolute ? "" :"-start+", size,
					    offset,
					    obj_size);
					append_trial(trials, START_SIZE_OFFSET_OBJECT_TRIAL(start, size, offset, obj_size, start_is_absolute, size_is_absolute, str));
				}
			}
		}
	}
	return trials;
}

#define SMART_START_SIZE_OFFSET_OBJECT_TRIALS()                                         \
	__attribute__((cleanup(cleanup_start_size_offset_object_trials)))               \
	= generate_start_size_offset_object_trials();

static void
cleanup_start_size_offset_object_trials(start_size_offset_object_trials_t **trials)
{
	for (size_t i = 0; i < (*trials)->count; i++) {
		kfree_str((*trials)->list[i].name);
	}
	free_trials(*trials);
}


// start/size/offset: test start+size and a second independent address
// consider src/dst/size instead if the size may be added to both addresses

typedef struct {
	mach_vm_address_t start;
	mach_vm_size_t size;
	vm_object_offset_t offset;
	bool start_is_absolute;
	bool size_is_absolute;
	char * name;
} start_size_offset_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	start_size_offset_trial_t list[];
} start_size_offset_trials_t;

TRIALS_IMPL(start_size_offset)

#define START_SIZE_OFFSET_TRIAL(new_start, new_size, new_offset, new_start_is_absolute, new_size_is_absolute, new_name) \
(start_size_offset_trial_t){ .start = (mach_vm_address_t)(new_start), \
	        .size = (mach_vm_size_t)(new_size), \
	        .offset = (vm_object_offset_t)(new_offset), \
	        .start_is_absolute = (bool)(new_start_is_absolute), \
	        .size_is_absolute = (bool)(new_size_is_absolute), \
	        .name = new_name,}


static start_size_offset_trial_t __attribute__((overloadable, used))
slide_trial(start_size_offset_trial_t trial, mach_vm_address_t slide)
{
	start_size_offset_trial_t result = trial;

	if (!trial.start_is_absolute) {
		result.start += slide;
		if (!trial.size_is_absolute) {
			result.size -= slide;
		}
	}
	return result;
}

start_size_offset_trials_t *
generate_start_size_offset_trials()
{
	const offset_list_t *start_offsets = get_ssoo_absolute_and_relative_offsets();
	const offset_list_t *offset_values = get_ssoo_absolute_offsets();
	const offset_list_t *size_offsets  = get_ssoo_absolute_and_relative_offsets();

	// output is actually ordered start - offset - size
	// because it pretty-prints better than start - size - offset
	unsigned num_trials = start_offsets->count * offset_values->count * size_offsets->count;
	start_size_offset_trials_t * trials = allocate_start_size_offset_trials(num_trials);
	for (size_t a = 0; a < start_offsets->count; a++) {
		for (size_t b = 0; b < offset_values->count; b++) {
			for (size_t c = 0; c < size_offsets->count; c++) {
				bool start_is_absolute = start_offsets->list[a].is_absolute;
				bool size_is_absolute = size_offsets->list[c].is_absolute;
				mach_vm_address_t start = start_offsets->list[a].offset;
				vm_object_offset_t offset = offset_values->list[b].offset;
				mach_vm_size_t size = size_offsets->list[c].offset;

				char *str;
				kasprintf(&str, "start: %s0x%llx, offset: 0x%llx, size: %s0x%llx",
				    start_is_absolute ? "" : "base+", start,
				    offset,
				    size_is_absolute ? "" :"-start+", size);
				append_trial(trials, START_SIZE_OFFSET_TRIAL(start, size, offset, start_is_absolute, size_is_absolute, str));
			}
		}
	}
	return trials;
}

#define SMART_START_SIZE_OFFSET_TRIALS()                                        \
	__attribute__((cleanup(cleanup_start_size_offset_trials)))              \
	= generate_start_size_offset_trials();

static void
cleanup_start_size_offset_trials(start_size_offset_trials_t **trials)
{
	for (size_t i = 0; i < (*trials)->count; i++) {
		kfree_str((*trials)->list[i].name);
	}
	free_trials(*trials);
}


// size/size: test two independent sizes

typedef struct {
	addr_t size;
	addr_t size_2;
	const char *name;
} size_size_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	size_size_trial_t list[];
} size_size_trials_t;

TRIALS_IMPL(size_size)

#define SIZE_SIZE_TRIAL(new_size, new_size_2, new_name) \
(size_size_trial_t){ .size = (addr_t)(new_size), \
	        .size_2 = (addr_t) (new_size_2), \
	        .name = new_name }

size_size_trials_t *
generate_size_size_trials()
{
	const offset_list_t *size_offsets = get_size_trial_offsets();
	unsigned SIZES = size_offsets->count;
	size_size_trials_t * trials = allocate_size_size_trials(SIZES * SIZES);

	for (size_t i = 0; i < SIZES; i++) {
		for (size_t j = 0; j < SIZES; j++) {
			addr_t size = size_offsets->list[i].offset;
			addr_t size_2 = size_offsets->list[j].offset;

			char *buf;
			kasprintf(&buf, "size:%lli, size2:%lli", (int64_t) size, size_2);
			append_trial(trials, SIZE_SIZE_TRIAL(size, size_2, buf));
		}
	}
	return trials;
}

#define SMART_SIZE_SIZE_TRIALS()                                                \
	__attribute__((cleanup(cleanup_size_size_trials)))              \
	= generate_size_size_trials();

static void
cleanup_size_size_trials(size_size_trials_t **trials)
{
	// TODO free strings in trials
	free_trials(*trials);
}


// src/dst/size: test a source address, a dest address,
// and a common size that may be added to both addresses

typedef struct {
	addr_t src;
	addr_t dst;
	addr_t size;
	char *name;
	bool src_is_absolute;  // src computation does not include any allocation's base address
	bool dst_is_absolute;  // dst computation does not include any allocation's base address
	bool size_is_src_relative;   // size computation includes src
	bool size_is_dst_relative;   // size computation includes dst
} src_dst_size_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	src_dst_size_trial_t list[];
} src_dst_size_trials_t;

TRIALS_IMPL(src_dst_size)

#define SRC_DST_SIZE_TRIAL(new_src, new_dst, new_size, new_name, src_absolute, dst_absolute, size_src_rel, size_dst_rel) \
	(src_dst_size_trial_t){                                         \
	        .src = (addr_t)(new_src),                               \
	        .dst = (addr_t)(new_dst),                               \
	        .size = (addr_t)(new_size),                             \
	        .name = new_name,                                       \
	        .src_is_absolute = src_absolute,                        \
	        .dst_is_absolute = dst_absolute,                        \
	        .size_is_src_relative = size_src_rel,                   \
	        .size_is_dst_relative = size_dst_rel,                   \
	}

src_dst_size_trials_t * __attribute__((overloadable))
generate_src_dst_size_trials(const char *srcname, const char *dstname)
{
	const offset_list_t *addr_offsets = get_addr_trial_offsets();
	const offset_list_t *size_offsets = get_size_trial_offsets();
	unsigned src_count = addr_offsets->count;
	unsigned dst_count = src_count;
	unsigned size_count = 3 * size_offsets->count;
	unsigned num_trials = src_count * dst_count * size_count;
	src_dst_size_trials_t * trials = allocate_src_dst_size_trials(num_trials);

	// each size is used three times:
	// once src-relative, once dst-relative, and once absolute
	unsigned size_part = size_count / 3;

	for (size_t i = 0; i < src_count; i++) {
		bool rebase_src = !addr_offsets->list[i].is_absolute;
		addr_t src_offset = addr_offsets->list[i].offset;

		for (size_t j = 0; j < dst_count; j++) {
			bool rebase_dst = !addr_offsets->list[j].is_absolute;
			addr_t dst_offset = addr_offsets->list[j].offset;

			for (size_t k = 0; k < size_count; k++) {
				bool rebase_size_from_src = false;
				bool rebase_size_from_dst = false;
				addr_t size_offset;
				if (k < size_part) {
					size_offset = size_offsets->list[k].offset;
				} else if (k < 2 * size_part) {
					size_offset = size_offsets->list[k - size_part].offset;
					rebase_size_from_src = true;
					rebase_size_from_dst = false;
				} else {
					size_offset = size_offsets->list[k - 2 * size_part].offset;
					rebase_size_from_src = false;
					rebase_size_from_dst = true;
				}

				addr_t size;
				char *desc;
				if (rebase_size_from_src) {
					size = -src_offset + size_offset;
					kasprintf(&desc, "%s: %s%lli, %s: %s%lli, size: -%s%+lli",
					    srcname, rebase_src ? "base+" : "", (int64_t)src_offset,
					    dstname, rebase_dst ? "base+" : "", (int64_t)dst_offset,
					    srcname, (int64_t)size_offset);
				} else if (rebase_size_from_dst) {
					size = -dst_offset + size_offset;
					kasprintf(&desc, "%s: %s%lli, %s: %s%lli, size: -%s%+lli",
					    srcname, rebase_src ? "base+" : "", (int64_t)src_offset,
					    dstname, rebase_dst ? "base+" : "", (int64_t)dst_offset,
					    dstname, (int64_t)size_offset);
				} else {
					size = size_offset;
					kasprintf(&desc, "%s: %s%lli, %s: %s%lli, size: %lli",
					    srcname, rebase_src ? "base+" : "", (int64_t)src_offset,
					    dstname, rebase_dst ? "base+" : "", (int64_t)dst_offset,
					    (int64_t)size_offset);
				}
				assert(desc);
				append_trial(trials, SRC_DST_SIZE_TRIAL(src_offset, dst_offset, size, desc,
				    !rebase_src, !rebase_dst, rebase_size_from_src, rebase_size_from_dst));
			}
		}
	}
	return trials;
}

src_dst_size_trials_t * __attribute__((overloadable))
generate_src_dst_size_trials(void)
{
	return generate_src_dst_size_trials("src", "dst");
}
#define SMART_SRC_DST_SIZE_TRIALS()                                     \
	__attribute__((cleanup(cleanup_src_dst_size_trials)))           \
	= generate_src_dst_size_trials();

#define SMART_FILEOFF_DST_SIZE_TRIALS()                                 \
	__attribute__((cleanup(cleanup_src_dst_size_trials)))           \
	= generate_src_dst_size_trials("fileoff", "dst");

static void
cleanup_src_dst_size_trials(src_dst_size_trials_t **trials)
{
	for (size_t i = 0; i < (*trials)->count; i++) {
		kfree_str((*trials)->list[i].name);
	}
	free_trials(*trials);
}

static src_dst_size_trial_t __attribute__((overloadable, used))
slide_trial_src(src_dst_size_trial_t trial, mach_vm_address_t slide)
{
	src_dst_size_trial_t result = trial;

	if (!trial.src_is_absolute) {
		result.src += slide;
		if (trial.size_is_src_relative) {
			result.size -= slide;
		}
	}
	return result;
}

static src_dst_size_trial_t __attribute__((overloadable, used))
slide_trial_dst(src_dst_size_trial_t trial, mach_vm_address_t slide)
{
	src_dst_size_trial_t result = trial;

	if (!trial.dst_is_absolute) {
		result.dst += slide;
		if (trial.size_is_dst_relative) {
			result.size -= slide;
		}
	}
	return result;
}


/////////////////////////////////////////////////////
// utility code

// Return true if flags has VM_FLAGS_FIXED
// This is non-trivial because VM_FLAGS_FIXED is zero;
// the real value is the absence of VM_FLAGS_ANYWHERE.
static inline bool
is_fixed(int flags)
{
	static_assert(VM_FLAGS_FIXED == 0, "this test requies VM_FLAGS_FIXED be zero");
	static_assert(VM_FLAGS_ANYWHERE != 0, "this test requires VM_FLAGS_ANYWHERE be nonzero");
	return !(flags & VM_FLAGS_ANYWHERE);
}

// Return true if flags has VM_FLAGS_FIXED and VM_FLAGS_OVERWRITE set.
static inline bool
is_fixed_overwrite(int flags)
{
	return is_fixed(flags) && (flags & VM_FLAGS_OVERWRITE);
}


// Return true if flags has VM_FLAGS_ANYWHERE and VM_FLAGS_RANDOM_ADDR set.
static inline bool
is_random_anywhere(int flags)
{
	static_assert(VM_FLAGS_ANYWHERE != 0, "this test requires VM_FLAGS_ANYWHERE be nonzero");
	return (flags & VM_FLAGS_RANDOM_ADDR) && (flags & VM_FLAGS_ANYWHERE);
}

// Deallocate [start, start+size).
// Don't deallocate if the allocator failed (allocator_kr)
// Don't deallocate if flags include FIXED | OVERWRITE (in which case
//   the memory is a pre-existing allocation and should be left alone)
static void
deallocate_if_not_fixed_overwrite(kern_return_t allocator_kr, MAP_T map,
    mach_vm_address_t start, mach_vm_size_t size, int flags)
{
	if (is_fixed_overwrite(flags)) {
		// fixed-overwrite with pre-existing allocation, don't deallocate
	} else if (allocator_kr != 0) {
		// allocator failed, don't deallocate
	} else {
		(void)mach_vm_deallocate(map, start, size);
	}
}

#if !KERNEL

// userspace: use the test task's own vm_map
#define SMART_MAP = mach_task_self()

#else

static inline vm_map_t
create_map(mach_vm_address_t map_start, mach_vm_address_t map_end)
{
	ledger_t ledger = ledger_instantiate(task_ledger_template, LEDGER_CREATE_ACTIVE_ENTRIES);
	pmap_t pmap = pmap_create_options(ledger, 0, PMAP_CREATE_64BIT);
	assert(pmap);
	ledger_dereference(ledger);  // now retained by pmap
	vm_map_t map = vm_map_create_options(pmap, map_start, map_end, VM_MAP_CREATE_PAGEABLE);
	assert(map);

	return map;
}

static inline void
cleanup_map(vm_map_t *map)
{
	assert(*map);
	kern_return_t kr = vm_map_terminate(*map);
	assert(kr == 0);
	vm_map_deallocate(*map);  // also destroys pmap
}

// kernel: create a new vm_map and deallocate it at end of scope
// fixme choose a user-like and a kernel-like address range
#define SMART_MAP                                                       \
	__attribute__((cleanup(cleanup_map))) = create_map(0, 0xffffffffffffffff)

#endif

// Allocate with an address hint.
// Important for kernel tests' empty vm_maps
// to avoid allocating near address 0 and ~0.
static kern_return_t
allocate_away_from_zero(
	MAP_T               map,
	mach_vm_address_t  *address,
	mach_vm_size_t      size)
{
	*address = 2ull * 1024 * 1024 * 1024; // 2 GB address hint
	return mach_vm_map(map, address, size,
	           0, VM_FLAGS_ANYWHERE, 0, 0, 0,
	           VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
}

// allocate a VM region with size and permissions
// and deallocate it at end of scope
#define SMART_ALLOCATE_VM(map, size, perm)                              \
    __attribute__((cleanup(cleanup_allocation))) = create_allocation(map, size, perm, false)

// allocate a VM region with size and permissions
// and deallocate it at end of scope
// If no such region could be allocated, return {.addr = 0}
#define SMART_TRY_ALLOCATE_VM(map, size, perm)                              \
    __attribute__((cleanup(cleanup_allocation))) = create_allocation(map, size, perm, true)

// a VM allocation with unallocated pages around it
typedef struct {
	MAP_T map;
	addr_t guard_size;
	addr_t guard_prefix;        // page-sized
	addr_t unallocated_prefix;  // page-sized
	addr_t addr;
	addr_t size;
	addr_t unallocated_suffix;  // page-sized
	addr_t guard_suffix;        // page-sized
} allocation_t;

static allocation_t
create_allocation(MAP_T new_map, mach_vm_address_t new_size, vm_prot_t perm, bool allow_failure)
{
	// allocations in address order:
	// 1 page guard_prefix (allocated, prot none)
	// 1 page unallocated_prefix (unallocated)
	// N pages addr..addr+size
	// 1 page unallocated_suffix (unallocated)
	// 1 page guard_suffix (allocated, prot none)

	// allocate new_size plus 4 pages
	// then carve it up into our regions

	allocation_t result;

	result.map = new_map;

	result.guard_size = KB16;
	result.size = round_up_page(new_size, KB16);
	if (result.size == 0 && allow_failure) {
		return (allocation_t){new_map, 0, 0, 0, 0, 0, 0, 0};
	}
	assert(result.size != 0);

	mach_vm_address_t allocated_base;
	mach_vm_size_t allocated_size = result.size;
	if (__builtin_add_overflow(result.size, result.guard_size * 4, &allocated_size)) {
		if (allow_failure) {
			return (allocation_t){new_map, 0, 0, 0, 0, 0, 0, 0};
		} else {
			assert(false);
		}
	}

	kern_return_t kr;
	kr = allocate_away_from_zero(result.map, &allocated_base, allocated_size);
	if (kr != 0 && allow_failure) {
		return (allocation_t){new_map, 0, 0, 0, 0, 0, 0, 0};
	}
	assert(kr == 0);

	result.guard_prefix = (addr_t)allocated_base;
	result.unallocated_prefix = result.guard_prefix + result.guard_size;
	result.addr = result.unallocated_prefix + result.guard_size;
	result.unallocated_suffix = result.addr + result.size;
	result.guard_suffix = result.unallocated_suffix + result.guard_size;

	kr = mach_vm_protect(result.map, result.addr, result.size, false, perm);
	assert(kr == 0);
	kr = mach_vm_protect(result.map, result.guard_prefix, result.guard_size, true, VM_PROT_NONE);
	assert(kr == 0);
	kr = mach_vm_protect(result.map, result.guard_suffix, result.guard_size, true, VM_PROT_NONE);
	assert(kr == 0);
	kr = mach_vm_deallocate(result.map, result.unallocated_prefix, result.guard_size);
	assert(kr == 0);
	kr = mach_vm_deallocate(result.map, result.unallocated_suffix, result.guard_size);
	assert(kr == 0);

	return result;
}

// Mark this allocation as deallocated by something else.
// This means cleanup_allocation() won't deallocate it twice.
// cleanup_allocation() will still free the guard pages.
static void
set_already_deallocated(allocation_t *allocation)
{
	allocation->addr = 0;
	allocation->size = 0;
}

static void
cleanup_allocation(allocation_t *allocation)
{
	// fixme verify allocations and unallocated spaces still exist where we expect
	if (allocation->size) {
		(void)mach_vm_deallocate(allocation->map, allocation->addr, allocation->size);
	}
	if (allocation->guard_size) {
		(void)mach_vm_deallocate(allocation->map, allocation->guard_prefix, allocation->guard_size);
		(void)mach_vm_deallocate(allocation->map, allocation->guard_suffix, allocation->guard_size);
	}
}


// unallocate a VM region with size
// and deallocate it at end of scope
#define SMART_UNALLOCATE_VM(map, size)                                  \
	__attribute__((cleanup(cleanup_unallocation))) = create_unallocation(map, size)

// unallocate a VM region with size
// and deallocate it at end of scope
// If no such region could be allocated, return {.addr = 0}
#define SMART_TRY_UNALLOCATE_VM(map, size)                                  \
	__attribute__((cleanup(cleanup_unallocation))) = create_unallocation(map, size, true)

// a VM space with allocated pages around it
typedef struct {
	MAP_T map;
	addr_t guard_size;
	addr_t guard_prefix;        // page-sized
	addr_t addr;
	addr_t size;
	addr_t guard_suffix;        // page-sized
} unallocation_t;

static unallocation_t __attribute__((overloadable))
create_unallocation(MAP_T new_map, mach_vm_address_t new_size, bool allow_failure)
{
	// allocations in address order:
	// 1 page guard_prefix (allocated, prot none)
	// N pages addr..addr+size (unallocated)
	// 1 page guard_suffix (allocated, prot none)

	// allocate new_size plus 2 pages
	// then carve it up into our regions

	unallocation_t result;

	result.map = new_map;

	result.guard_size = KB16;
	result.size = round_up_page(new_size, KB16);
	if (result.size == 0 && allow_failure) {
		return (unallocation_t){new_map, 0, 0, 0, 0, 0};
	}
	assert(result.size != 0);

	mach_vm_address_t allocated_base;
	mach_vm_size_t allocated_size = result.size;
	if (__builtin_add_overflow(result.size, result.guard_size * 2, &allocated_size)) {
		if (allow_failure) {
			return (unallocation_t){new_map, 0, 0, 0, 0, 0};
		} else {
			assert(false);
		}
	}
	kern_return_t kr;
	kr = allocate_away_from_zero(result.map, &allocated_base, allocated_size);
	if (kr != 0 && allow_failure) {
		return (unallocation_t){new_map, 0, 0, 0, 0, 0};
	}
	assert(kr == 0);

	result.guard_prefix = (addr_t)allocated_base;
	result.addr = result.guard_prefix + result.guard_size;
	result.guard_suffix = result.addr + result.size;

	kr = mach_vm_deallocate(result.map, result.addr, result.size);
	assert(kr == 0);
	kr = mach_vm_protect(result.map, result.guard_prefix, result.guard_size, true, VM_PROT_NONE);
	assert(kr == 0);
	kr = mach_vm_protect(result.map, result.guard_suffix, result.guard_size, true, VM_PROT_NONE);
	assert(kr == 0);

	return result;
}

static unallocation_t __attribute__((overloadable))
create_unallocation(MAP_T new_map, mach_vm_address_t new_size)
{
	return create_unallocation(new_map, new_size, false /*allow_failure*/);
}

static void
cleanup_unallocation(unallocation_t *unallocation)
{
	// fixme verify allocations and unallocated spaces still exist where we expect
	if (unallocation->guard_size) {
		(void)mach_vm_deallocate(unallocation->map, unallocation->guard_prefix, unallocation->guard_size);
		(void)mach_vm_deallocate(unallocation->map, unallocation->guard_suffix, unallocation->guard_size);
	}
}


// mach_vm_remap_external/vm_remap_external/vm32_remap/mach_vm_remap_new_external infra
// mach_vm_remap/mach_vm_remap_new_kernel infra

typedef kern_return_t (*remap_fn_t)(vm_map_t target_task,
    mach_vm_address_t *target_address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    vm_map_t src_task,
    mach_vm_address_t src_address,
    boolean_t copy,
    vm_prot_t *cur_protection,
    vm_prot_t *max_protection,
    vm_inherit_t inheritance);

// helpers that call a provided function with certain sets of params

static kern_return_t
help_call_remap_fn__src_size_etc(remap_fn_t fn, MAP_T map, int flags, bool copy, mach_vm_address_t src, mach_vm_size_t size, vm_prot_t cur, vm_prot_t max, vm_inherit_t inherit)
{
	kern_return_t kr;
#if KERNEL
	if (is_random_anywhere(flags)) {
		// RANDOM_ADDR is likely to fall outside pmap's range
		return PANIC;
	}
#endif
	if (is_fixed_overwrite(flags)) {
		// Try to allocate a dest for vm_remap to fixed-overwrite at.
		allocation_t dst_alloc SMART_TRY_ALLOCATE_VM(map, size, VM_PROT_DEFAULT);
		mach_vm_address_t out_addr = dst_alloc.addr;
		if (out_addr == 0) {
			// Failed to allocate. Clear VM_FLAGS_OVERWRITE
			// to prevent wild mappings.
			flags &= ~VM_FLAGS_OVERWRITE;
		}
		kr = fn(map, &out_addr, size, 0, flags,
		    map, src, copy, &cur, &max, inherit);
	} else {
		// vm_remap will allocate anywhere. Deallocate if it succeeds.
		mach_vm_address_t out_addr = 0;
		kr = fn(map, &out_addr, size, 0, flags,
		    map, src, copy, &cur, &max, inherit);
		if (kr == 0) {
			(void)mach_vm_deallocate(map, out_addr, size);
		}
	}
	return kr;
}

static kern_return_t
help_call_remap_fn__src_size(remap_fn_t fn, MAP_T map, int unused_flags __unused, bool copy, mach_vm_address_t src, mach_vm_size_t size)
{
	assert(unused_flags == 0);
	return help_call_remap_fn__src_size_etc(fn, map, VM_FLAGS_ANYWHERE, copy, src, size, 0, 0, VM_INHERIT_NONE);
}

static kern_return_t
help_call_remap_fn__dst_size(remap_fn_t fn, MAP_T map, int flags, bool copy, mach_vm_address_t dst, mach_vm_size_t size)
{
	allocation_t src SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	mach_vm_address_t out_addr = dst;
	vm_prot_t cur = 0;
	vm_prot_t max = 0;
	kern_return_t kr = fn(map, &out_addr, size, 0, flags,
	    map, src.addr, copy, &cur, &max, VM_INHERIT_NONE);
	deallocate_if_not_fixed_overwrite(kr, map, out_addr, size, flags);
	return kr;
}

static kern_return_t
help_call_remap_fn__inherit(remap_fn_t fn, MAP_T map, int flags, bool copy, mach_vm_address_t src, mach_vm_size_t size, vm_inherit_t inherit)
{
	return help_call_remap_fn__src_size_etc(fn, map, flags, copy, src, size, 0, 0, inherit);
}

static kern_return_t
help_call_remap_fn__flags(remap_fn_t fn, MAP_T map, int unused_flags __unused, bool copy, mach_vm_address_t src, mach_vm_size_t size, int trial_flags)
{
	assert(unused_flags == 0);
	return help_call_remap_fn__src_size_etc(fn, map, trial_flags, copy, src, size, 0, 0, VM_INHERIT_NONE);
}

static kern_return_t
help_call_remap_fn__prot_pairs(remap_fn_t fn, MAP_T map, int flags, bool copy, mach_vm_address_t src, mach_vm_size_t size, vm_prot_t cur, vm_prot_t max)
{
	return help_call_remap_fn__src_size_etc(fn, map, flags, copy, src, size, cur, max, VM_INHERIT_NONE);
}

static kern_return_t
help_call_remap_fn__src_dst_size(remap_fn_t fn, MAP_T map, int flags, bool copy, mach_vm_address_t src, mach_vm_size_t size, mach_vm_address_t dst)
{
	mach_vm_address_t out_addr = dst;
	vm_prot_t cur = 0;
	vm_prot_t max = 0;
	kern_return_t kr = fn(map, &out_addr, size, 0, flags,
	    map, src, copy, &cur, &max, VM_INHERIT_NONE);
	deallocate_if_not_fixed_overwrite(kr, map, out_addr, size, flags);
	return kr;
}

#define GET_INSTANCE(_0, _1, _2, _3, _4, _5, _6, _7, _8, NAME, ...) NAME

#define DROP_TYPES_8(a, b, ...) , b DROP_TYPES_6(__VA_ARGS__)
#define DROP_TYPES_6(a, b, ...) , b DROP_TYPES_4(__VA_ARGS__)
#define DROP_TYPES_4(a, b, ...) , b DROP_TYPES_2(__VA_ARGS__)
#define DROP_TYPES_2(a, b, ...) , b
#define DROP_TYPES_0()

// Parses lists of "type1, arg1, type2, arg" into "arg1, arg2"
#define DROP_TYPES(...) GET_INSTANCE(_0 __VA_OPT__(,) __VA_ARGS__, DROP_TYPES_8, DROP_TYPES_8, DROP_TYPES_6, DROP_TYPES_6, DROP_TYPES_4, DROP_TYPES_4, DROP_TYPES_2, DROP_TYPES_2, DROP_TYPES_0, DROP_TYPES_0)(__VA_ARGS__)

#define DROP_COMMAS_8(a, b, ...) , a b DROP_COMMAS_6(__VA_ARGS__)
#define DROP_COMMAS_6(a, b, ...) , a b DROP_COMMAS_4(__VA_ARGS__)
#define DROP_COMMAS_4(a, b, ...) , a b DROP_COMMAS_2(__VA_ARGS__)
#define DROP_COMMAS_2(a, b) , a b
#define DROP_COMMAS_0()

// Parses lists of "type1, arg1, type2, arg" into "type1 arg1, type2 arg2"
#define DROP_COMMAS(...) GET_INSTANCE(_0 __VA_OPT__(,) __VA_ARGS__, DROP_COMMAS_8, DROP_COMMAS_8, DROP_COMMAS_6, DROP_COMMAS_6, DROP_COMMAS_4, DROP_COMMAS_4, DROP_COMMAS_2, DROP_COMMAS_2, DROP_COMMAS_0)(__VA_ARGS__)

// specialize helpers into implementations of call functions that are still agnostic to the remap function

#define IMPL_ONE_FROM_HELPER(type, variant, flags, copy, ...)                                                                                           \
	static kern_return_t                                                                                                                            \
	call_remap_fn ## __ ## variant ## __ ## type(remap_fn_t fn, MAP_T map, mach_vm_address_t src, mach_vm_size_t size DROP_COMMAS(__VA_ARGS__)) {   \
	        return help_call_remap_fn__ ## type(fn, map, flags, copy, src, size DROP_TYPES(__VA_ARGS__));                                           \
	}

#define IMPL_FROM_HELPER(type, ...) \
	IMPL_ONE_FROM_HELPER(type, fixed, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, false, ##__VA_ARGS__)         \
	IMPL_ONE_FROM_HELPER(type, fixed_copy, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, true, ##__VA_ARGS__)     \
	IMPL_ONE_FROM_HELPER(type, anywhere, VM_FLAGS_ANYWHERE, false, ##__VA_ARGS__)   \

IMPL_FROM_HELPER(dst_size);
IMPL_FROM_HELPER(inherit, vm_inherit_t, inherit);
IMPL_FROM_HELPER(prot_pairs, vm_prot_t, cur, vm_prot_t, max);
IMPL_FROM_HELPER(src_dst_size, mach_vm_address_t, dst);

IMPL_ONE_FROM_HELPER(flags, nocopy, 0 /*ignored*/, false, int, flag)
IMPL_ONE_FROM_HELPER(flags, copy, 0 /*ignored*/, true, int, flag)

IMPL_ONE_FROM_HELPER(src_size, nocopy, 0 /*ignored*/, false)
IMPL_ONE_FROM_HELPER(src_size, copy, 0 /*ignored*/, true)

#undef IMPL_FROM_HELPER
#undef IMPL_ONE_FROM_HELPER

// define call functions that are specific to the remap function, and rely on implementations above under the hood

#define IMPL_REMAP_FN_HELPER(remap_fn, instance, type, ...)                                             \
    static kern_return_t                                                                                \
    call_ ## remap_fn ## __ ## instance ## __ ## type(MAP_T map DROP_COMMAS(__VA_ARGS__))               \
    {                                                                                                   \
	return call_remap_fn__ ## instance ## __ ## type(remap_fn, map DROP_TYPES(__VA_ARGS__));        \
    }

#define IMPL_REMAP_FN_SRC_SIZE(remap_fn, instance) IMPL_REMAP_FN_HELPER(remap_fn, instance, src_size, mach_vm_address_t, src, mach_vm_size_t, size)
#define IMPL_REMAP_FN_DST_SIZE(remap_fn, instance) IMPL_REMAP_FN_HELPER(remap_fn, instance, dst_size, mach_vm_address_t, src, mach_vm_size_t, size)
#define IMPL_REMAP_FN_SRC_DST_SIZE(remap_fn, instance) IMPL_REMAP_FN_HELPER(remap_fn, instance, src_dst_size, mach_vm_address_t, src, mach_vm_size_t, size, mach_vm_address_t, dst)
#define IMPL_REMAP_FN_SRC_SIZE_INHERIT(remap_fn, instance) IMPL_REMAP_FN_HELPER(remap_fn, instance, inherit, mach_vm_address_t, src, mach_vm_size_t, size, vm_inherit_t, inherit)
#define IMPL_REMAP_FN_SRC_SIZE_FLAGS(remap_fn, instance) IMPL_REMAP_FN_HELPER(remap_fn, instance, flags, mach_vm_address_t, src, mach_vm_size_t, size, int, flags)
#define IMPL_REMAP_FN_PROT_PAIRS(remap_fn, instance) IMPL_REMAP_FN_HELPER(remap_fn, instance, prot_pairs, mach_vm_address_t, src, mach_vm_size_t, size, vm_prot_t, cur, vm_prot_t, max)

#define IMPL(remap_fn)                                          \
	IMPL_REMAP_FN_SRC_SIZE(remap_fn, nocopy);               \
	IMPL_REMAP_FN_SRC_SIZE(remap_fn, copy);                 \
                                                                \
	IMPL_REMAP_FN_DST_SIZE(remap_fn, fixed);                \
	IMPL_REMAP_FN_DST_SIZE(remap_fn, fixed_copy);           \
	IMPL_REMAP_FN_DST_SIZE(remap_fn, anywhere);             \
                                                                \
	IMPL_REMAP_FN_SRC_SIZE_INHERIT(remap_fn, fixed);        \
	IMPL_REMAP_FN_SRC_SIZE_INHERIT(remap_fn, fixed_copy);   \
	IMPL_REMAP_FN_SRC_SIZE_INHERIT(remap_fn, anywhere);     \
                                                                \
	IMPL_REMAP_FN_SRC_SIZE_FLAGS(remap_fn, nocopy);         \
	IMPL_REMAP_FN_SRC_SIZE_FLAGS(remap_fn, copy);           \
                                                                \
	IMPL_REMAP_FN_PROT_PAIRS(remap_fn, fixed);              \
	IMPL_REMAP_FN_PROT_PAIRS(remap_fn, fixed_copy);         \
	IMPL_REMAP_FN_PROT_PAIRS(remap_fn, anywhere);           \
                                                                \
	IMPL_REMAP_FN_SRC_DST_SIZE(remap_fn, fixed);            \
	IMPL_REMAP_FN_SRC_DST_SIZE(remap_fn, fixed_copy);       \
	IMPL_REMAP_FN_SRC_DST_SIZE(remap_fn, anywhere);         \

static inline void
check_mach_vm_map_outparam_changes(kern_return_t * kr, mach_vm_address_t addr, mach_vm_address_t saved_addr,
    int flags, MAP_T map)
{
	if (*kr == KERN_SUCCESS) {
		if (is_fixed(flags)) {
			if (addr != truncate_vm_map_addr_with_flags(map, saved_addr, flags)) {
				*kr = OUT_PARAM_BAD;
			}
		}
	} else {
		if (addr != saved_addr) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

static inline void
check_mach_vm_remap_outparam_changes(kern_return_t * kr, mach_vm_address_t addr, mach_vm_address_t saved_addr,
    int flags, vm_prot_t cur_prot, vm_prot_t saved_cur_prot, vm_prot_t max_prot, vm_prot_t saved_max_prot, MAP_T map,
    mach_vm_address_t src_addr)
{
	if (*kr == KERN_SUCCESS) {
		if (is_fixed(flags)) {
			mach_vm_address_t expected_misalignment = get_expected_remap_misalignment(map, src_addr, flags);
			if (addr != trunc_down_map(map, saved_addr) + expected_misalignment) {
				*kr = OUT_PARAM_BAD;
			}
		}
	} else {
		if ((addr != saved_addr) || (cur_prot != saved_cur_prot) ||
		    (max_prot != saved_max_prot)) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

#if KERNEL

static bool
dealloc_would_panic(mach_vm_address_t start, mach_vm_size_t size);

static inline kern_return_t
mach_vm_remap_wrapped_kern(vm_map_t target_task,
    mach_vm_address_t *target_address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    vm_map_t src_task,
    mach_vm_address_t src_address,
    boolean_t copy,
    vm_prot_t *cur_protection,
    vm_prot_t *max_protection,
    vm_inherit_t inheritance)
{
	if (dealloc_would_panic(*target_address, size)) {
		return PANIC;
	}
	mach_vm_address_t saved_addr = *target_address;
	vm_prot_t saved_cur_prot = *cur_protection;
	vm_prot_t saved_max_prot = *max_protection;
	kern_return_t kr = mach_vm_remap(target_task, target_address, size, mask, flags, src_task, src_address, copy, cur_protection, max_protection, inheritance);
	check_mach_vm_remap_outparam_changes(&kr, *target_address, saved_addr, flags,
	    *cur_protection, saved_cur_prot, *max_protection, saved_max_prot, target_task, src_address);
	return kr;
}
IMPL(mach_vm_remap_wrapped_kern)

static inline kern_return_t
mach_vm_remap_new_kernel_wrapped(vm_map_t target_task,
    mach_vm_address_t *target_address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    vm_map_t src_task,
    mach_vm_address_t src_address,
    boolean_t copy,
    vm_prot_t *cur_protection,
    vm_prot_t *max_protection,
    vm_inherit_t inheritance)
{
	if (dealloc_would_panic(*target_address, size)) {
		return PANIC;
	}
	mach_vm_address_t saved_addr = *target_address;
	vm_prot_t saved_cur_prot = *cur_protection;
	vm_prot_t saved_max_prot = *max_protection;
	kern_return_t kr = mach_vm_remap_new_kernel(target_task, target_address, size, mask, FLAGS_AND_TAG(flags, VM_KERN_MEMORY_OSFMK), src_task, src_address, copy, cur_protection, max_protection, inheritance);
	// remap_new sets VM_FLAGS_RETURN_DATA_ADDR
	check_mach_vm_remap_outparam_changes(&kr, *target_address, saved_addr, flags | VM_FLAGS_RETURN_DATA_ADDR,
	    *cur_protection, saved_cur_prot, *max_protection, saved_max_prot, target_task, src_address);
	return kr;
}
IMPL(mach_vm_remap_new_kernel_wrapped)

#else /* !KERNEL */

static inline kern_return_t
mach_vm_remap_user(vm_map_t target_task,
    mach_vm_address_t *target_address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    vm_map_t src_task,
    mach_vm_address_t src_address,
    boolean_t copy,
    vm_prot_t *cur_protection,
    vm_prot_t *max_protection,
    vm_inherit_t inheritance)
{
	mach_vm_address_t saved_addr = *target_address;
	vm_prot_t saved_cur_prot = *cur_protection;
	vm_prot_t saved_max_prot = *max_protection;
	kern_return_t kr = mach_vm_remap(target_task, target_address, size, mask, flags, src_task, src_address, copy, cur_protection, max_protection, inheritance);
	check_mach_vm_remap_outparam_changes(&kr, *target_address, saved_addr, flags,
	    *cur_protection, saved_cur_prot, *max_protection, saved_max_prot, target_task, src_address);
	return kr;
}
IMPL(mach_vm_remap_user)

static inline kern_return_t
mach_vm_remap_new_user(vm_map_t target_task,
    mach_vm_address_t *target_address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    vm_map_t src_task,
    mach_vm_address_t src_address,
    boolean_t copy,
    vm_prot_t *cur_protection,
    vm_prot_t *max_protection,
    vm_inherit_t inheritance)
{
	mach_vm_address_t saved_addr = *target_address;
	vm_prot_t saved_cur_prot = *cur_protection;
	vm_prot_t saved_max_prot = *max_protection;
	kern_return_t kr = mach_vm_remap_new(target_task, target_address, size, mask, flags, src_task, src_address, copy, cur_protection, max_protection, inheritance);
	// remap_new sets VM_FLAGS_RETURN_DATA_ADDR
	check_mach_vm_remap_outparam_changes(&kr, *target_address, saved_addr, flags | VM_FLAGS_RETURN_DATA_ADDR,
	    *cur_protection, saved_cur_prot, *max_protection, saved_max_prot, target_task, src_address);
	return kr;
}
IMPL(mach_vm_remap_new_user)

#if TEST_OLD_STYLE_MACH
static inline kern_return_t
vm_remap_retyped(vm_map_t target_task,
    mach_vm_address_t *target_address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    vm_map_t src_task,
    mach_vm_address_t src_address,
    boolean_t copy,
    vm_prot_t *cur_protection,
    vm_prot_t *max_protection,
    vm_inherit_t inheritance)
{
	vm_address_t addr = (vm_address_t)*target_address;
	vm_prot_t saved_cur_prot = *cur_protection;
	vm_prot_t saved_max_prot = *max_protection;
	kern_return_t kr = vm_remap(target_task, &addr, (vm_size_t)size, (vm_address_t)mask, flags, src_task, (vm_address_t)src_address, copy, cur_protection, max_protection, inheritance);
	check_mach_vm_remap_outparam_changes(&kr, addr, (vm_address_t) *target_address, flags,
	    *cur_protection, saved_cur_prot, *max_protection, saved_max_prot, target_task, src_address);
	*target_address = addr;
	return kr;
}

IMPL(vm_remap_retyped)

#endif /* TEST_OLD_STYLE_MACH */
#endif /* !KERNEL */

#undef IMPL
#undef IMPL_REMAP_FN_SRC_SIZE
#undef IMPL_REMAP_FN_DST_SIZE
#undef IMPL_REMAP_FN_SRC_DST_SIZE
#undef IMPL_REMAP_FN_SRC_SIZE_INHERIT
#undef IMPL_REMAP_FN_SRC_SIZE_FLAGS
#undef IMPL_REMAP_FN_PROT_PAIRS
#undef IMPL_REMAP_FN_HELPER


/////////////////////////////////////////////////////
// Test runners for functions with commonly-used parameter types and setup code.

#define IMPL(NAME, T)                                                   \
	/* Test a Mach function */                                      \
	/* Run each trial with an allocated vm region and start/size parameters that reference it. */ \
	typedef kern_return_t (*NAME ## mach_with_start_size_fn)(MAP_T map, T start, T size); \
                                                                        \
	static results_t * __attribute__((used))                        \
	     test_ ## NAME ## mach_with_allocated_start_size(NAME ## mach_with_start_size_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        start_size_trials_t *trials SMART_START_SIZE_TRIALS(base.addr); \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                T start = (T)trials->list[i].start;             \
	                T size = (T)trials->list[i].size;               \
	                kern_return_t ret = fn(map, start, size);       \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
	/* Test a Mach function. */                                     \
	/* Run each trial with an allocated vm region and an addr parameter that reference it. */ \
	typedef kern_return_t (*NAME ## mach_with_addr_fn)(MAP_T map, T addr); \
                                                                        \
	static results_t * __attribute__((used))                        \
	        test_ ## NAME ## mach_with_allocated_addr_of_size_n(NAME ## mach_with_addr_fn fn, size_t obj_size, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        addr_trials_t *trials SMART_ADDR_TRIALS(base.addr);     \
	/* Do all the addr trials and an additional trial such that obj_size + addr == 0 */ \
	        results_t *results = alloc_results(testname, trials->count+1); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                T addr = (T)trials->list[i].addr;               \
	                kern_return_t ret = fn(map, addr);              \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        kern_return_t ret = fn(map,  - ((T) obj_size));         \
	        char *trial_desc;                                       \
	        kasprintf(&trial_desc, "addr: -0x%lx", obj_size);       \
	        append_result(results, ret, trial_desc);                \
	        kfree_str(trial_desc);                                  \
	        return results;                                         \
	}                                                               \
                                                                        \
	/* Test a Mach function. */                                     \
	/* Run each trial with an allocated vm region and an addr parameter that reference it. */ \
	typedef kern_return_t (*NAME ## mach_with_addr_fn)(MAP_T map, T addr); \
                                                                        \
	static results_t * __attribute__((used))                        \
	        test_ ## NAME ## mach_with_allocated_addr(NAME ## mach_with_addr_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        addr_trials_t *trials SMART_ADDR_TRIALS(base.addr);     \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                T addr = (T)trials->list[i].addr;               \
	                kern_return_t ret = fn(map, addr);              \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
                                                                        \
	/* Test a Mach function. */                                     \
	/* Run each trial with a size parameter. */                     \
	typedef kern_return_t (*NAME ## mach_with_size_fn)(MAP_T map, T size); \
                                                                        \
	static results_t * __attribute__((used))                        \
	        test_ ## NAME ## mach_with_size(NAME ## mach_with_size_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        size_trials_t *trials SMART_SIZE_TRIALS();              \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                T size = (T)trials->list[i].size;               \
	                kern_return_t ret = fn(map, size);              \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
                                                                        \
	/* Test a Mach function. */                                     \
	/* Run each trial with a size parameter. */                     \
	typedef kern_return_t (*NAME ## mach_with_start_size_offset_object_fn)(MAP_T map, T addr, T size, T offset, T obj_size); \
                                                                        \
	static results_t * __attribute__((used))                        \
	        test_ ## NAME ## mach_with_start_size_offset_object(NAME ## mach_with_start_size_offset_object_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        start_size_offset_object_trials_t *trials SMART_START_SIZE_OFFSET_OBJECT_TRIALS(); \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                start_size_offset_object_trial_t trial = slide_trial(trials->list[i], base.addr); \
	                T start = (T)trial.start;                       \
	                T size = (T)trial.size;                         \
	                T offset = (T)trial.offset;                     \
	                T obj_size = (T)trial.obj_size;                 \
	                kern_return_t ret = fn(map, start, size, offset, obj_size); \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
	/* Test a Mach function. */                                     \
	/* Run each trial with a size parameter. */                     \
	typedef kern_return_t (*NAME ## mach_with_start_size_offset_fn)(MAP_T map, T addr, T size, T offset, T obj_size); \
                                                                        \
	static results_t * __attribute__((used))                        \
	        test_ ## NAME ## mach_with_start_size_offset(NAME ## mach_with_start_size_offset_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        start_size_offset_trials_t *trials SMART_START_SIZE_OFFSET_TRIALS(); \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                start_size_offset_trial_t trial = slide_trial(trials->list[i], base.addr); \
	                T start = (T)trial.start;                       \
	                T size = (T)trial.size;                         \
	                T offset = (T)trial.offset;                     \
	                kern_return_t ret = fn(map, start, size, offset, 1); \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
                                                                        \
	/* Test a Mach function. */                                     \
	/* Run each trial with an allocated vm region and a set of mmap flags. */ \
	typedef kern_return_t (*NAME ## mach_with_allocated_mmap_flags_fn)(MAP_T map, T addr, T size, int flags); \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_allocated_mmap_flags(NAME ## mach_with_allocated_mmap_flags_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        mmap_flags_trials_t *trials SMART_MMAP_FLAGS_TRIALS();  \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                int flags = trials->list[i].flags;              \
	                kern_return_t ret = fn(map, (T)base.addr, (T)base.size, flags); \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
                                                                        \
	/* Test a Mach function. */                                     \
	/* Run each trial with an allocated vm region and a generic 32 bit flag. */ \
	typedef kern_return_t (*NAME ## mach_with_allocated_generic_flag)(MAP_T map, T addr, T size, int flag); \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_allocated_generic_flag(NAME ## mach_with_allocated_generic_flag fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        generic_flag_trials_t *trials SMART_GENERIC_FLAG_TRIALS();      \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                int flag = trials->list[i].flag;                \
	                kern_return_t ret = fn(map, (T)base.addr, (T)base.size, flag); \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
                                                                        \
	/* Test a Mach function. */                                     \
	/* Run each trial with a vm_prot_t. */                          \
	typedef kern_return_t (*NAME ## mach_with_prot_fn)(MAP_T map, T size, vm_prot_t prot); \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_vm_prot(NAME ## mach_with_prot_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        vm_prot_trials_t *trials SMART_VM_PROT_TRIALS();        \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                kern_return_t ret = fn(map, TEST_ALLOC_SIZE, trials->list[i].prot); \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
                                                                        \
	/* Test a Mach function. */                                     \
	/* Run each trial with a pair of vm_prot_t's. */                \
	typedef kern_return_t (*NAME ## mach_with_prot_pair_fn)(MAP_T map, vm_prot_t cur, vm_prot_t max); \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_vm_prot_pair(NAME ## mach_with_prot_pair_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        vm_prot_pair_trials_t *trials SMART_VM_PROT_PAIR_TRIALS();      \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                kern_return_t ret = fn(map, trials->list[i].cur, trials->list[i].max); \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
                                                                        \
	/* Test a Mach function. */                                     \
	/* Run each trial with a pair of vm_prot_t's. */ \
	typedef kern_return_t (*NAME ## mach_with_allocated_prot_pair_fn)(MAP_T map, T addr, T size, vm_prot_t cur, vm_prot_t max); \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_allocated_vm_prot_pair(NAME ## mach_with_allocated_prot_pair_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        vm_prot_pair_trials_t *trials SMART_VM_PROT_PAIR_TRIALS(); \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                kern_return_t ret = fn(map, (T)base.addr, (T)base.size, trials->list[i].cur, trials->list[i].max); \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
                                                                        \
	/* Test a Mach function. */                                     \
	/* Run each trial with an allocated vm region and a vm_prot_t. */ \
	typedef kern_return_t (*NAME ## mach_with_allocated_prot_fn)(MAP_T map, T addr, T size, vm_prot_t prot); \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_allocated_vm_prot_t(NAME ## mach_with_allocated_prot_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        vm_prot_trials_t *trials SMART_VM_PROT_TRIALS();        \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                vm_prot_t prot = trials->list[i].prot;          \
	                kern_return_t ret = fn(map, (T)base.addr, (T)base.size, prot); \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
                                                                        \
	/* Test a Mach function. */                                     \
	/* Run each trial with a ledger flag. */ \
	typedef kern_return_t (*NAME ## mach_ledger_flag_fn)(MAP_T map, int ledger_flag); \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_ledger_flag(NAME ## mach_ledger_flag_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        ledger_flag_trials_t *trials SMART_LEDGER_FLAG_TRIALS();        \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                kern_return_t ret = fn(map, trials->list[i].flag); \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
	/* Test a Mach function. */                                     \
	/* Run each trial with a ledger tag. */                         \
	typedef kern_return_t (*NAME ## mach_ledger_tag_fn)(MAP_T map, int ledger_tag); \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_ledger_tag(NAME ## mach_ledger_tag_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        ledger_tag_trials_t *trials SMART_LEDGER_TAG_TRIALS();  \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                kern_return_t ret = fn(map, trials->list[i].tag); \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
                                                                        \
	/* Test a Mach function. */                                     \
	/* Run each trial with an allocated region and a vm_inherit_t. */ \
	typedef kern_return_t (*NAME ## mach_inherit_fn)(MAP_T map, T addr, T size, vm_inherit_t inherit); \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_allocated_vm_inherit_t(NAME ## mach_inherit_fn fn, const char * testname) { \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        vm_inherit_trials_t *trials SMART_VM_INHERIT_TRIALS();  \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                vm_inherit_trial_t trial = trials->list[i];     \
	                int ret = fn(map, (T)base.addr, (T)base.size, trial.value); \
	                append_result(results, ret, trial.name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
	/* Test a Mach function. */                                     \
	/* Run each trial with an allocated vm region and a vm_prot_t. */ \
	typedef kern_return_t (*NAME ## with_start_end_fn)(MAP_T map, T addr, T end); \
                                                                        \
	static results_t * __attribute__((used))                        \
	        test_ ## NAME ## with_start_end(NAME ## with_start_end_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        start_size_trials_t *trials SMART_START_SIZE_TRIALS(base.addr); \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                T start = (T)trials->list[i].start;             \
	                T size = (T)trials->list[i].size;               \
	                kern_return_t ret = fn(map, start, start + size);       \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
	/* Test a Mach function. */                                     \
	/* Run each trial with an allocated vm region and a vm_prot_t. */ \
	typedef kern_return_t (*NAME ## with_tag_fn)(MAP_T map, T addr, T end, vm_tag_t tag); \
                                                                        \
	static results_t * __attribute__((used))                        \
	        test_ ## NAME ## with_tag(NAME ## with_tag_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        vm_tag_trials_t *trials SMART_VM_TAG_TRIALS();  \
	        results_t *results = alloc_results(testname, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                kern_return_t ret = fn(map, base.addr, base.addr + base.size, trials->list[i].tag); \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}

IMPL(, uint64_t)
#if TEST_OLD_STYLE_MACH
IMPL(old, uint32_t)
#endif
#undef IMPL

// Test a mach allocation function with a start/size
static results_t *
test_mach_allocation_func_with_start_size(kern_return_t (*func)(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size), const char * testname)
{
	MAP_T map SMART_MAP;
	start_size_trials_t *trials SMART_START_SIZE_TRIALS(0);
	results_t *results = alloc_results(testname, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		unallocation_t dst SMART_UNALLOCATE_VM(map, TEST_ALLOC_SIZE);
		start_size_trial_t trial = slide_trial(trials->list[i], dst.addr);
		mach_vm_address_t addr = trial.start;
		kern_return_t ret = func(map, &addr, trial.size);
		if (ret == 0) {
			(void)mach_vm_deallocate(map, addr, trial.size);
		}
		append_result(results, ret, trial.name);
	}
	return results;
}

// Test a mach allocation function with a vm_map_kernel_flags_t
static results_t *
test_mach_allocation_func_with_vm_map_kernel_flags_t(kern_return_t (*func)(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size, int flags), const char * testname)
{
	MAP_T map SMART_MAP;
	vm_map_kernel_flags_trials_t * trials SMART_VM_MAP_KERNEL_FLAGS_TRIALS();
	results_t *results = alloc_results(testname, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		allocation_t fixed_overwrite_dst SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
		vm_map_kernel_flags_trial_t trial = trials->list[i];
#if KERNEL
		if (is_random_anywhere(trial.flags)) {
			// RANDOM_ADDR is likely to fall outside pmap's range
			append_result(results, PANIC, trial.name);
			continue;
		}
#endif
		mach_vm_address_t addr = 0;
		if (is_fixed_overwrite(trial.flags)) {
			// use a pre-existing destination for fixed-overwrite
			addr = fixed_overwrite_dst.addr;
		}
		kern_return_t ret = func(map, &addr, TEST_ALLOC_SIZE, trial.flags);
		deallocate_if_not_fixed_overwrite(ret, map, addr, TEST_ALLOC_SIZE, trial.flags);
		append_result(results, ret, trial.name);
	}
	return results;
}

static results_t *
test_mach_with_allocated_vm_map_kernel_flags_t(kern_return_t (*func)(MAP_T map, mach_vm_address_t src, mach_vm_size_t size, int flags), const char * testname)
{
	MAP_T map SMART_MAP;

	allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	vm_map_kernel_flags_trials_t * trials SMART_VM_MAP_KERNEL_FLAGS_TRIALS();
	results_t *results = alloc_results(testname, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		kern_return_t ret = func(map, base.addr, base.size, trials->list[i].flags);
		append_result(results, ret, trials->list[i].name);
	}
	return results;
}

static results_t *
test_mmap_with_allocated_vm_map_kernel_flags_t(kern_return_t (*func)(MAP_T map, mach_vm_address_t src, mach_vm_size_t size, int flags), const char * testname)
{
	MAP_T map SMART_MAP;

	allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	vm_map_kernel_flags_trials_t * trials SMART_MMAP_KERNEL_FLAGS_TRIALS();
	results_t *results = alloc_results(testname, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		kern_return_t ret = func(map, base.addr, base.size, trials->list[i].flags);
		append_result(results, ret, trials->list[i].name);
	}
	return results;
}


// Test a Unix function.
// Run each trial with an allocated vm region and start/size parameters that reference it.
typedef int (*unix_with_start_size_fn)(void *start, size_t size);

static results_t * __unused
test_unix_with_allocated_start_size(unix_with_start_size_fn fn, const char *testname)
{
	MAP_T map SMART_MAP;
	allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	start_size_trials_t *trials SMART_START_SIZE_TRIALS(base.addr);
	results_t *results = alloc_results(testname, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		addr_t start = trials->list[i].start;
		addr_t size = trials->list[i].size;
		int ret = fn((void*)(uintptr_t)start, (size_t)size);
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
	results_t *results = alloc_results(testname, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		vm_inherit_trial_t trial = trials->list[i];
		int ret = fn((void*)(uintptr_t)base.addr, (size_t)base.size, (int)trial.value);
		append_result(results, ret, trial.name);
	}
	return results;
}


#ifdef KERNEL
static results_t * __unused
test_kext_unix_with_allocated_start_size(unix_with_start_size_fn fn, const char *testname)
{
	allocation_t base SMART_ALLOCATE_VM(current_map(), TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	start_size_trials_t *trials SMART_START_SIZE_TRIALS(base.addr);
	results_t *results = alloc_results(testname, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		addr_t start = trials->list[i].start;
		addr_t size = trials->list[i].size;
		int ret = fn((void*)(uintptr_t)start, (size_t)size);
		append_result(results, ret, trials->list[i].name);
	}
	return results;
}

/* Test a Kext function requiring memory allocated with a specific tag. */
/* Run each trial with an allocated vm region and an addr parameter that reference it. */

static results_t * __attribute__((used))
test_kext_tagged_with_allocated_addr(kern_return_t (*func)(MAP_T map, mach_vm_address_t addr), const char *testname)
{
	allocation_t base SMART_ALLOCATE_VM(current_map(), TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	addr_trials_t *trials SMART_ADDR_TRIALS(base.addr);
	results_t *results = alloc_results(testname, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		mach_vm_address_t addr = (mach_vm_address_t)trials->list[i].addr;
		kern_return_t ret = func(current_map(), addr);
		append_result(results, ret, trials->list[i].name);
	}
	return results;
}
#endif /* KERNEL */

static results_t * __attribute__((used))
test_with_int64(kern_return_t (*func)(int64_t), const char *testname)
{
	size_trials_t *trials SMART_SIZE_TRIALS();
	results_t *results = alloc_results(testname, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		int64_t val = (int64_t)trials->list[i].size;
		kern_return_t ret = func(val);
		append_result(results, ret, trials->list[i].name);
	}
	return results;
}


#if !KERNEL

// For deallocators like munmap and vm_deallocate.
// Return a non-zero error code if we should avoid performing this trial.
// Call this BEFORE sliding the trial to a non-zero base address.
extern
kern_return_t
short_circuit_deallocator(MAP_T map, start_size_trial_t trial);

// implemented in vm_parameter_validation.c

#else /* KERNEL */

static inline
kern_return_t
short_circuit_deallocator(MAP_T map __unused, start_size_trial_t trial __unused)
{
	// Kernel tests run with an empty vm_map so we're free to deallocate whatever we want.
	return 0;
}

#endif /* KERNEL */


// Test mach_vm_deallocate or munmap.
// Similar to test_mach_with_allocated_addr_size, but mach_vm_deallocate is destructive
// so we can't test all values and we need to re-allocate the vm allocation each time.
static results_t *
test_deallocator(kern_return_t (*func)(MAP_T map, mach_vm_address_t start, mach_vm_size_t size), const char *testname)
{
	MAP_T map SMART_MAP;

	// allocate trials relative to address zero
	// later we slide them to each allocation's address
	start_size_trials_t *trials SMART_START_SIZE_TRIALS(0);

	results_t *results = alloc_results(testname, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		start_size_trial_t trial = trials->list[i];
		allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);

		// Avoid trials that might deallocate wildly.
		// Check this BEFORE sliding the trial.
		kern_return_t ret = short_circuit_deallocator(map, trial);
		if (ret == 0) {
			// Adjust start and/or size, if that value includes the allocated address
			trial = slide_trial(trial, base.addr);

			ret = func(map, trial.start, trial.size);
			if (ret == 0) {
				// Deallocation succeeded. Don't deallocate again.
				set_already_deallocated(&base);
			}
		}
		append_result(results, ret, trial.name);
	}

	return results;
}

static results_t *
test_allocated_src_unallocated_dst_size(kern_return_t (*func)(MAP_T map, mach_vm_address_t src, mach_vm_size_t size, mach_vm_address_t dst), const char * testname)
{
	MAP_T map SMART_MAP;
	allocation_t src_base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	src_dst_size_trials_t * trials SMART_SRC_DST_SIZE_TRIALS();
	results_t *results = alloc_results(testname, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		src_dst_size_trial_t trial = trials->list[i];
		unallocation_t dst_base SMART_UNALLOCATE_VM(map, TEST_ALLOC_SIZE);
		trial = slide_trial_src(trial, src_base.addr);
		trial = slide_trial_dst(trial, dst_base.addr);
		int ret = func(map, trial.src, trial.size, trial.dst);
		// func deallocates its own allocation
		append_result(results, ret, trial.name);
	}
	return results;
}

static results_t *
test_allocated_src_allocated_dst_size(kern_return_t (*func)(MAP_T map, mach_vm_address_t src, mach_vm_size_t size, mach_vm_address_t dst), const char * testname)
{
	MAP_T map SMART_MAP;
	allocation_t src_base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	allocation_t dst_base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	src_dst_size_trials_t * trials SMART_SRC_DST_SIZE_TRIALS();
	results_t *results = alloc_results(testname, trials->count);

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

static results_t *
test_dst_size_fileoff(kern_return_t (*func)(MAP_T map, mach_vm_address_t dst, mach_vm_size_t size, mach_vm_address_t fileoff), const char * testname)
{
	MAP_T map SMART_MAP;
	src_dst_size_trials_t * trials SMART_FILEOFF_DST_SIZE_TRIALS();
	results_t *results = alloc_results(testname, trials->count);

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
	results_t *results = alloc_results(testname, trials->count);
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
	results_t *results = alloc_results(testname, trials->count);
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


static bool
will_wire_function_panic_due_to_alignment(mach_vm_address_t start, mach_vm_address_t end)
{
	// Start and end must be page aligned
	if (start & PAGE_MASK) {
		return true;
	}
	if (end & PAGE_MASK) {
		return true;
	}
	return false;
}

/*
 * This function is basically trying to determine if this address is one vm_wire would find in the vm_map and attempt to wire.
 * This is because due to the environment in which our test runs, vm_tag_bt() returns VM_KERN_MEMORY_NONE.
 * Trying to wire with VM_KERN_MEMORY_NONE results in a panic due to asserts in VM_OBJECT_WIRED_PAGE_UPDATE_END.
 */
static bool
will_wire_function_panic_due_to_vm_tag(mach_vm_address_t addr)
{
	return (addr > (KB16 * 2)) && (addr < (-KB16 * 2));
}

static inline void
check_mach_vm_allocate_outparam_changes(kern_return_t * kr, mach_vm_address_t addr, mach_vm_size_t size,
    mach_vm_address_t saved_start, int flags, MAP_T map)
{
	if (*kr == KERN_SUCCESS) {
		if (size == 0) {
			if (addr != 0) {
				*kr = OUT_PARAM_BAD;
			}
		} else {
			if (is_fixed(flags)) {
				if (addr != trunc_down_map(map, saved_start)) {
					*kr = OUT_PARAM_BAD;
				}
			}
		}
	} else {
		if (saved_start != addr) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

#pragma clang diagnostic pop

// VM_PARAMETER_VALIDATION_H
#endif
