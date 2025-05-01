#ifndef VM_PARAMETER_VALIDATION_H
#define VM_PARAMETER_VALIDATION_H


/*
 * Common Naming Conventions:
 * call_* functions are harnesses used to call a single function under test.
 * They take all arguments needed to call the function and avoid calling functions with PANICing values.
 * test_* functions are used to call the call_ functions. They iterate through possibilities of interesting parameters
 * and provide those as arguments to the call_ functions.
 *
 * test_* functions are named in the following way:
 * Arguments under test are put at the end of the name. e.g. (test_mach_vm_prot) tests a vm_prot_t
 * test_mach_... functions test a function with the first argument being a MAP_T.
 * test_unix_... functions test a unix-y function. This means it doesn't take a MAP_T.
 * In kernel context, it means it operates on current_map instead of an arbitrary vm_map_t
 * test_..._with_allocated_... means an allocation has already been created, and some parameters referring to that allocation are passed in.
 *
 * Common Abbreviations:
 * ssz: Start + Start + Size
 * ssoo: Start + Size + Offset + Object
 * sso: Start + Start + Offset
 */

#include <sys/mman.h>
#if KERNEL

#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <mach/vm_reclaim.h>
#include <mach/vm_reclaim_private.h>
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

#define FLAGS_AND_TAG(f, t) ({                             \
	vm_map_kernel_flags_t vmk_flags;                   \
	vm_map_kernel_flags_set_vmflags(&vmk_flags, f, t); \
	vmk_flags;                                         \
})

#else  // KERNEL

#include <TargetConditionals.h>

#endif // KERNEL


// ignore some warnings inside this file
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeclaration-after-statement"
#pragma clang diagnostic ignored "-Wincompatible-function-pointer-types"
#pragma clang diagnostic ignored "-Wmissing-prototypes"
#pragma clang diagnostic ignored "-Wpedantic"
#pragma clang diagnostic ignored "-Wgcc-compat"

/*
 * Invalid values for various types. These are used by the outparameter tests.
 * UNLIKELY_ means the value is not 100% guaranteed to be invalid for that type,
 * and is just a very unlikely value for it. Tests should not rely on them to compare against UNLIKELY_
 * values without explicit reason it cannot be possible.
 *
 * INVALID_* means the value is 100% guaranteed to be invalid. They can be relied on to be compared against.
 */

#define UNLIKELY_INITIAL_ADDRESS 0xabababab
/*
 * It's important for us to never have a test with a size like
 * UNLIKELY_INITIAL_SIZE, and for this to stay non page aligned.
 * See comment in call_mach_memory_entry_map_size__start_size for more info
 */
#define UNLIKELY_INITIAL_SIZE 0xabababab
#define UNLIKELY_INITIAL_PPNUM 0xabababab
#define UNLIKELY_INITIAL_MACH_PORT ((mach_port_t) 0xbabababa)
#define UNLIKELY_INITIAL_VID 0xbabababa
// This cannot possibly be a valid vnode pointer as they are pointers
#define INVALID_VNODE_PTR ((void *) -1)
// This cannot possibly be a valid vm_map_copy_t as they are pointers
#define INVALID_VM_MAP_COPY ((vm_map_copy_t) (void *) -1)
// This cannot be a purgable state (see vm_purgable.h) It's way above the last valid state
#define INVALID_PURGABLE_STATE 0xababab
static_assert(INVALID_PURGABLE_STATE > VM_PURGABLE_STATE_MAX, "This test requires a purgable state above the max");
// Disposition values are generated via the VM_PAGE_QUERY_ values being ored.
// This cannot be a valid one as it's above the greatest possible or
#define INVALID_DISPOSITION_VALUE 0xffffff0
#define INVALID_INHERIT 0xbaba
static_assert(INVALID_INHERIT > VM_INHERIT_LAST_VALID, "This test requires an inheritance above the max");

#define INVALID_INITIAL_VID 0xbabababa
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
	vm_sanitize_map_round_page_mask(T addr, uint64_t pagemask) {                      \
	        return (addr + (T)pagemask) & ~((T)pagemask);           \
	}                                                               \
                                                                        \
	/* Round up to the given page size. */                          \
	__attribute__((overloadable, used))                             \
	static inline T                                                 \
	round_up_page(T addr, uint64_t pagesize) {                      \
	        return vm_sanitize_map_round_page_mask(addr, pagesize - 1);               \
	}                                                               \
                                                                        \
	/* Round up to the given map's page size. */                    \
	__attribute__((overloadable, used))                             \
	static inline T                                                 \
	round_up_map(MAP_T map, T addr) {                               \
	        return vm_sanitize_map_round_page_mask(addr, VM_MAP_PAGE_MASK(map));      \
	}                                                               \
                                                                        \
	/* Truncate to the given page mask. */                          \
	__attribute__((overloadable, used))                             \
	static inline T                                                 \
	vm_sanitize_map_trunc_page_mask(T addr, uint64_t pagemask)                      \
	{                                                               \
	        return addr & ~((T)pagemask);                           \
	}                                                               \
                                                                        \
	/* Truncate to the given page size. */                          \
	__attribute__((overloadable, used))                             \
	static inline T                                                 \
	trunc_down_page(T addr, uint64_t pagesize)                      \
	{                                                               \
	        return vm_sanitize_map_trunc_page_mask(addr, pagesize - 1);             \
	}                                                               \
                                                                        \
	/* Truncate to the given map's page size. */                    \
	__attribute__((overloadable, used))                             \
	static inline T                                                 \
	trunc_down_map(MAP_T map, T addr)                               \
	{                                                               \
	        return vm_sanitize_map_trunc_page_mask(addr, VM_MAP_PAGE_MASK(map));    \
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
	vm_sanitize_range_overflows_allow_zero(T start, T size, T pgmask)           \
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
	        T aligned_start = vm_sanitize_map_trunc_page_mask(start, pgmask);       \
	        T aligned_end = vm_sanitize_map_round_page_mask(start + size, pgmask);    \
	        if (aligned_end <= aligned_start) {                     \
	                return true;                                    \
	        }                                                       \
                                                                        \
	        return false;                                           \
	}                                                               \
                                                                        \
	/* like vm_sanitize_range_overflows_allow_zero(), but without the */        \
	/* unconditional approval of size==0 */                         \
	__attribute__((overloadable, used))                             \
	static bool                                                     \
	vm_sanitize_range_overflows_strict_zero(T start, T size, T pgmask)                      \
	{                                                               \
	        T sum;                                                  \
	        if (__builtin_add_overflow(start, size, &sum)) {        \
	                return true;                                    \
	        }                                                       \
                                                                        \
	        T aligned_start = vm_sanitize_map_trunc_page_mask(start, pgmask);       \
	        T aligned_end = vm_sanitize_map_round_page_mask(start + size, pgmask);    \
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

// Needed to distinguish between rosetta kernel runs and generating trials names from kern golden files.
#if KERNEL
#define kern_trialname_generation FALSE
#else
static bool kern_trialname_generation = FALSE;
#endif
static addr_t trial_page_size = 0;

static inline addr_t
adjust_page_size()
{
	addr_t test_page_size = PAGE_SIZE;
#if !KERNEL && __x86_64__
	// Handle kernel page size variation while recreating trials names for golden files in userspace.
	if (kern_trialname_generation && isRosetta()) {
		test_page_size = trial_page_size;
	}
#endif //  !KERNEL && __x86_64__
	return test_page_size;
}

#if KERNEL
// Knobs controlled from userspace (and passed in MSB of the file_descriptor)
extern bool kernel_generate_golden;
#else
// Knobs controlled by environment variables
extern bool dump;
extern bool generate_golden;
extern bool dump_golden;
extern int out_param_bad_count;
extern bool should_test_results;
static void
read_env()
{
	dump = (getenv("DUMP_RESULTS") != NULL);
	dump_golden = (getenv("DUMP_GOLDEN_IMAGE") != NULL);
	// Shouldn't do both
	generate_golden = (getenv("GENERATE_GOLDEN_IMAGE") != NULL) && !dump_golden;
	// Only test when no other golden image flag is set
	should_test_results = (getenv("SKIP_TESTS") == NULL) && !dump_golden && !generate_golden;
}
#endif


/////////////////////////////////////////////////////
// String functions that work in both kernel and userspace.

// Test output function.
// This prints either to stdout (userspace tests) or to a userspace buffer (kernel sysctl tests)
// Golden tests generation in userspace also writes to a buffer (GOLDEN_OUTPUT_BUF)
#if KERNEL
extern void testprintf(const char *, ...) __printflike(1, 2);
#define goldenprintf testprintf
#else
#define testprintf printf
extern void goldenprintf(const char *, ...) __printflike(1, 2);
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

// Maintain list of known trials "smart" generator functions (trial formulae) as
// these are included in the golden result list (keeping the enum forces people to
// maintain the list up-to-date when adding new functions).
#define TRIALSFORMULA_ENUM(VARIANT) \
	VARIANT(eUNKNOWN_TRIALS) \
	VARIANT(eSMART_VM_MAP_KERNEL_FLAGS_TRIALS) \
	VARIANT(eSMART_VM_INHERIT_TRIALS) \
	VARIANT(eSMART_MMAP_KERNEL_FLAGS_TRIALS) \
	VARIANT(eSMART_MMAP_FLAGS_TRIALS) \
	VARIANT(eSMART_GENERIC_FLAG_TRIALS) \
	VARIANT(eSMART_VM_TAG_TRIALS) \
	VARIANT(eSMART_VM_PROT_TRIALS) \
	VARIANT(eSMART_VM_PROT_PAIR_TRIALS) \
	VARIANT(eSMART_LEDGER_TAG_TRIALS) \
	VARIANT(eSMART_LEDGER_FLAG_TRIALS) \
	VARIANT(eSMART_ADDR_TRIALS) \
	VARIANT(eSMART_SIZE_TRIALS) \
	VARIANT(eSMART_START_SIZE_TRIALS) \
	VARIANT(eSMART_START_SIZE_OFFSET_OBJECT_TRIALS) \
	VARIANT(eSMART_START_SIZE_OFFSET_TRIALS) \
	VARIANT(eSMART_SIZE_SIZE_TRIALS) \
	VARIANT(eSMART_SRC_DST_SIZE_TRIALS) \
	VARIANT(eSMART_FILEOFF_DST_SIZE_TRIALS) \
	VARIANT(eSMART_VM_BEHAVIOR_TRIALS) \
	VARIANT(eSMART_VM_ADVISE_TRIALS) \
	VARIANT(eSMART_VM_SYNC_TRIALS) \
	VARIANT(eSMART_VM_MSYNC_TRIALS) \
	VARIANT(eSMART_VM_MACHINE_ATTRIBUTE_TRIALS) \
	VARIANT(eSMART_VM_PURGEABLE_AND_STATE_TRIALS) \
	VARIANT(eSMART_START_SIZE_START_SIZE_TRIALS) \
	VARIANT(eSMART_SHARED_REGION_MAP_AND_SLIDE_2_TRIALS) \
	VARIANT(eSMART_RECLAMATION_BUFFER_INIT_TRIALS)

#define TRIALSFORMULA_ENUM_VARIANT(NAME) NAME,
typedef enum {
	TRIALSFORMULA_ENUM(TRIALSFORMULA_ENUM_VARIANT)
} trialsformula_t;

#define TRIALSARGUMENTS_NONE 0
#define TRIALSARGUMENTS_SIZE 2

// formula enum id to string
#define TRIALSFORMULA_ENUM_STRING(NAME) case NAME: return #NAME;
const char *
trialsformula_name(trialsformula_t formula)
{
	switch (formula) {
		TRIALSFORMULA_ENUM(TRIALSFORMULA_ENUM_STRING)
	default:
		testprintf("Unknown formula_t %d\n", formula);
		assert(false);
	}
}

#define TRIALSFORMULA_ENUM_FROM_STRING(NAME)    \
	if (strncmp(string, #NAME, strlen(#NAME)) == 0) return NAME;

// formula name to enum id
trialsformula_t
trialsformula_from_string(const char *string)
{
	TRIALSFORMULA_ENUM(TRIALSFORMULA_ENUM_FROM_STRING)
	// else
	testprintf("Unknown formula %s\n", string);
	assert(false);
}

// ret: return value of this trial
// name: name of this trial, including the input values passed in
typedef struct {
	int ret;
	char *name;
} result_t;

typedef struct {
	const char *testname;
	char *testconfig;
	trialsformula_t trialsformula;
	uint64_t trialsargs[TRIALSARGUMENTS_SIZE];
	unsigned capacity;
	unsigned count;
	unsigned tested_count;
	result_t list[];
} results_t;

extern results_t *golden_list[];
extern results_t *kern_list[];
static uint32_t num_tests = 0; // num of tests in golden list
static uint32_t num_kern_tests = 0; // num of tests in kernel results list

static __attribute__((overloadable))
results_t *
alloc_results(const char *testname, char *testconfig,
    trialsformula_t trialsformula, uint64_t trialsargs[static TRIALSARGUMENTS_SIZE],
    unsigned capacity)
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
	results->trialsformula = trialsformula;
	for (unsigned i = 0; i < TRIALSARGUMENTS_SIZE; i++) {
		results->trialsargs[i] = trialsargs[i];
	}
	results->capacity = capacity;
	results->count = 0;
	results->tested_count = 0;
	return results;
}

static char *
alloc_default_testconfig(void)
{
	char *result;
	kasprintf(&result, "%s %s %s%s",
	    OS_NAME, ARCH_NAME,
	    kern_trialname_generation ? "kernel" : CALLER_NAME,
	    !kern_trialname_generation && isRosetta() ? " rosetta" : "");
	return result;
}

static __attribute__((overloadable))
results_t *
alloc_results(const char *testname,
    trialsformula_t trialsformula, uint64_t *trialsargs, size_t trialsargs_count,
    unsigned capacity)
{
	assert(trialsargs_count == TRIALSARGUMENTS_SIZE);
	return alloc_results(testname, alloc_default_testconfig(), trialsformula, trialsargs, capacity);
}

static __attribute__((overloadable))
results_t *
alloc_results(const char *testname, trialsformula_t trialsformula, uint64_t trialsarg0, unsigned capacity)
{
	uint64_t trialsargs[TRIALSARGUMENTS_SIZE] = {trialsarg0, TRIALSARGUMENTS_NONE};
	return alloc_results(testname, trialsformula, trialsargs, TRIALSARGUMENTS_SIZE, capacity);
}

static __attribute__((overloadable))
results_t *
alloc_results(const char *testname, trialsformula_t trialsformula, unsigned capacity)
{
	uint64_t trialsargs[TRIALSARGUMENTS_SIZE] = {TRIALSARGUMENTS_NONE, TRIALSARGUMENTS_NONE};
	return alloc_results(testname, trialsformula, trialsargs, TRIALSARGUMENTS_SIZE, capacity);
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


#define TESTNAME_DELIMITER        "TESTNAME "
#define RESULTCOUNT_DELIMITER     "RESULT COUNT "
#define TESTRESULT_DELIMITER      " "
#define TESTCONFIG_DELIMITER      "  TESTCONFIG "
#define TRIALSFORMULA_DELIMITER   "TRIALSFORMULA "
#define TRIALSARGUMENTS_DELIMITER "TRIALSARGUMENTS"
#define KERN_TESTRESULT_DELIMITER "  RESULT "

// print results, unformatted
// This output is read by populate_kernel_results()
// and by tools/format_vm_parameter_validation.py
static results_t *
__dump_results(results_t *results)
{
	testprintf(TESTNAME_DELIMITER "%s\n", results->testname);
	testprintf(RESULTCOUNT_DELIMITER "%d\n", results->count);
	testprintf(TESTCONFIG_DELIMITER "%s\n", results->testconfig);

	for (unsigned i = 0; i < results->count; i++) {
		testprintf(KERN_TESTRESULT_DELIMITER "%d, %s\n", results->list[i].ret, results->list[i].name);
	}

	results->tested_count += 1;
	return results;
}

// This output is read by populate_golden_results()
static results_t *
dump_golden_results(results_t *results)
{
	trial_page_size = PAGE_SIZE;
	goldenprintf(TESTNAME_DELIMITER "%s\n", results->testname);
	goldenprintf(TRIALSFORMULA_DELIMITER "%s %s %llu,%llu,%llu\n",
	    trialsformula_name(results->trialsformula), TRIALSARGUMENTS_DELIMITER,
	    results->trialsargs[0], results->trialsargs[1], trial_page_size);
	goldenprintf(RESULTCOUNT_DELIMITER "%d\n", results->count);

	for (unsigned i = 0; i < results->count; i++) {
		goldenprintf(TESTRESULT_DELIMITER "%d: %d\n", i, results->list[i].ret);
#if !KERNEL
		if (results->list[i].ret == OUT_PARAM_BAD) {
			out_param_bad_count += 1;
			T_FAIL("Out parameter violation in test %s - %s\n", results->testname, results->list[i].name);
		}
#endif
	}

	return results;
}

#if !KERNEL
// Comparator function for sorting result_t list by name
static int
compare_names(const void *a, const void *b)
{
	assert(((const result_t *)a)->name);
	assert(((const result_t *)b)->name);
	return strcmp(((const result_t *)a)->name, ((const result_t *)b)->name);
}

static unsigned
binary_search(result_t *list, unsigned count, const result_t *trial)
{
	assert(count > 0);
	const char *name = trial->name;
	unsigned left = 0, right = count - 1;
	while (left <= right) {
		unsigned mid = left + (right - left) / 2;
		int cmp = strcmp(list[mid].name, name);
		if (cmp == 0) {
			return mid;
		} else if (cmp < 0) {
			left = mid + 1;
		} else {
			right = mid - 1;
		}
	}
	return UINT_MAX; // Not found
}

static inline bool
trial_name_equals(const result_t *a, const result_t *b)
{
	// NB: strlen match need to handle cases where a shorter 'bname' would match a longer 'aname'.
	if (strlen(a->name) == strlen(b->name) && compare_names(a, b) == 0) {
		return true;
	}
	return false;
}

static const result_t *
get_golden_result(results_t *golden_results, const result_t *trial, unsigned trial_idx)
{
	if (golden_results->trialsformula == eUNKNOWN_TRIALS) {
		// golden results don't contain trials names
		T_LOG("%s: update test's alloc_results to have a valid trialsformula_t\n", golden_results->testname);
		return NULL;
	}

	if (trial_idx < golden_results->count &&
	    golden_results->list[trial_idx].name &&
	    trial_name_equals(&golden_results->list[trial_idx], trial)) {
		// "fast search" path taken when golden file is in sync to test.
		return &golden_results->list[trial_idx];
	}

	// "slow search" path taken when tests idxs are not aligned. Sort the array
	// by name and do binary search.
	qsort(golden_results->list, golden_results->count, sizeof(result_t), compare_names);
	unsigned g_idx = binary_search(golden_results->list, golden_results->count, trial);
	if (g_idx < golden_results->count) {
		return &golden_results->list[g_idx];
	}

	return NULL;
}

static void
test_results(results_t *golden_results, results_t *results)
{
	bool passed = TRUE;
	unsigned result_count = results->count;
	unsigned acceptable_count = 0;
	const unsigned acceptable_max = 16;  // log up to this many ACCEPTABLE results
	const result_t *golden_result = NULL;
	if (golden_results->count != results->count) {
		T_LOG("%s: number of iterations mismatch (%u vs %u)",
		    results->testname, golden_results->count, results->count);
	}
	for (unsigned i = 0; i < result_count; i++) {
		golden_result = get_golden_result(golden_results, &results->list[i], i);
		if (golden_result) {
			if (results->list[i].ret == ACCEPTABLE) {
				// trial has declared itself to be correct
				// no matter what the golden result is
				acceptable_count++;
				if (acceptable_count <= acceptable_max) {
					T_LOG("%s RESULT ACCEPTABLE (expected %d), %s\n",
					    results->testname,
					    golden_result->ret, results->list[i].name);
				}
			} else if (results->list[i].ret != golden_result->ret) {
				T_FAIL("%s RESULT %d (expected %d), %s\n",
				    results->testname, results->list[i].ret,
				    golden_result->ret, results->list[i].name);
				passed = FALSE;
			}
		} else {
			// new trial not present in golden results
			T_FAIL("%s NEW RESULT %d, %s - (regenerate golden files to fix this)\n",
			    results->testname, results->list[i].ret, results->list[i].name);
			passed = FALSE;
		}
	}

	if (acceptable_count > acceptable_max) {
		T_LOG("%s %u more RESULT ACCEPTABLE trials not logged\n",
		    results->testname, acceptable_count - acceptable_max);
	}
	if (passed) {
		T_PASS("%s passed\n", results->testname);
	}
}
#endif

#if !KERNEL
static results_t *
test_name_to_golden_results(const char* testname);
#endif

static results_t *
process_results(results_t *results)
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

	if (should_test_results) {
		golden_results = test_name_to_golden_results(results->testname);

		if (golden_results) {
			test_results(golden_results, results);
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
	__attribute__((used))                                       \
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
	(vm_inherit_trial_t) {.value = (vm_inherit_t)(new_value), .name = "vm_inherit " #new_value}

static_assert(VM_INHERIT_LAST_VALID == VM_INHERIT_NONE,
    "Update this test with new vm_inherit_t values");
static vm_inherit_trial_t vm_inherit_trials_values[] = {
	VM_INHERIT_TRIAL(VM_INHERIT_SHARE),
	VM_INHERIT_TRIAL(VM_INHERIT_COPY),
	VM_INHERIT_TRIAL(VM_INHERIT_NONE),
	// end valid ones
	// note: VM_INHERIT_DONATE_COPY is invalid and unimplemented
	// VM_INHERIT_LAST_VALID correctly excludes VM_INHERIT_DONATE_COPY
	VM_INHERIT_TRIAL(VM_INHERIT_LAST_VALID + 1),
	VM_INHERIT_TRIAL(VM_INHERIT_LAST_VALID + 2),
	VM_INHERIT_TRIAL(0xffffffff),
};

TRIALS_IMPL(vm_inherit)

static void
cleanup_vm_inherit_trials(vm_inherit_trials_t **trials)
{
	free_trials(*trials);
}

// allocate vm_behavior_t trials, and deallocate it at end of scope
#define SMART_VM_BEHAVIOR_TRIALS()                                               \
	__attribute__((cleanup(cleanup_vm_behavior_trials)))             \
	= allocate_vm_behavior_trials(countof(vm_behavior_trials_values));        \
	append_trials(trials, vm_behavior_trials_values, countof(vm_behavior_trials_values))

// generate vm_behavior_t trials

typedef struct {
	vm_behavior_t value;
	const char * name;
} vm_behavior_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	vm_behavior_trial_t list[];
} vm_behavior_trials_t;


#define VM_BEHAVIOR_TRIAL(new_value) \
	(vm_behavior_trial_t) {.value = (vm_behavior_t)(new_value), .name = "vm_behavior " #new_value}

static vm_behavior_trial_t vm_behavior_trials_values[] = {
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_DEFAULT),
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_RANDOM),
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_SEQUENTIAL),
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_RSEQNTL),
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_WILLNEED),
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_DONTNEED),
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_FREE),
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_ZERO_WIRED_PAGES),
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_REUSABLE),
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_REUSE),
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_CAN_REUSE),
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_PAGEOUT),
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_ZERO),
	// end valid ones
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_LAST_VALID + 1),
	VM_BEHAVIOR_TRIAL(VM_BEHAVIOR_LAST_VALID + 2),
	VM_BEHAVIOR_TRIAL(0x12345),
	VM_BEHAVIOR_TRIAL(0xffffffff),
};

TRIALS_IMPL(vm_behavior)

static void
cleanup_vm_behavior_trials(vm_behavior_trials_t **trials)
{
	free_trials(*trials);
}

// allocate vm_sync_t trials, and deallocate it at end of scope
#define SMART_VM_SYNC_TRIALS()                                               \
	__attribute__((cleanup(cleanup_vm_sync_trials)))             \
	= allocate_vm_sync_trials(countof(vm_sync_trials_values));        \
	append_trials(trials, vm_sync_trials_values, countof(vm_sync_trials_values))

// generate vm_sync_t trials

typedef struct {
	vm_sync_t value;
	const char * name;
} vm_sync_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	vm_sync_trial_t list[];
} vm_sync_trials_t;


#define VM_SYNC_TRIAL(new_value) \
	(vm_sync_trial_t) {.value = (vm_sync_t)(new_value), .name = "vm_sync_t " #new_value}

static vm_sync_trial_t vm_sync_trials_values[] = {
	VM_SYNC_TRIAL(0),
	// start valid values
	VM_SYNC_TRIAL(VM_SYNC_ASYNCHRONOUS),
	VM_SYNC_TRIAL(VM_SYNC_SYNCHRONOUS),
	VM_SYNC_TRIAL(VM_SYNC_INVALIDATE),
	VM_SYNC_TRIAL(VM_SYNC_KILLPAGES),
	VM_SYNC_TRIAL(VM_SYNC_DEACTIVATE),
	VM_SYNC_TRIAL(VM_SYNC_CONTIGUOUS),
	VM_SYNC_TRIAL(VM_SYNC_REUSABLEPAGES),
	// end valid values
	VM_SYNC_TRIAL(1u << 7),
	VM_SYNC_TRIAL(1u << 8),
	VM_SYNC_TRIAL(1u << 9),
	VM_SYNC_TRIAL(1u << 10),
	VM_SYNC_TRIAL(1u << 11),
	VM_SYNC_TRIAL(1u << 12),
	VM_SYNC_TRIAL(1u << 13),
	VM_SYNC_TRIAL(1u << 14),
	VM_SYNC_TRIAL(1u << 15),
	VM_SYNC_TRIAL(1u << 16),
	VM_SYNC_TRIAL(1u << 17),
	VM_SYNC_TRIAL(1u << 18),
	VM_SYNC_TRIAL(1u << 19),
	VM_SYNC_TRIAL(1u << 20),
	VM_SYNC_TRIAL(1u << 21),
	VM_SYNC_TRIAL(1u << 22),
	VM_SYNC_TRIAL(1u << 23),
	VM_SYNC_TRIAL(1u << 24),
	VM_SYNC_TRIAL(1u << 25),
	VM_SYNC_TRIAL(1u << 26),
	VM_SYNC_TRIAL(1u << 27),
	VM_SYNC_TRIAL(1u << 28),
	VM_SYNC_TRIAL(1u << 29),
	VM_SYNC_TRIAL(1u << 30),
	VM_SYNC_TRIAL(1u << 31),
	VM_SYNC_TRIAL(VM_SYNC_ASYNCHRONOUS | VM_SYNC_SYNCHRONOUS),
	VM_SYNC_TRIAL(VM_SYNC_ASYNCHRONOUS | (1u << 7)),
	VM_SYNC_TRIAL(0xffffffff),
};

TRIALS_IMPL(vm_sync)

static void
cleanup_vm_sync_trials(vm_sync_trials_t **trials)
{
	free_trials(*trials);
}

// allocate vm_msync_t trials, and deallocate it at end of scope
#define SMART_VM_MSYNC_TRIALS()                                               \
	__attribute__((cleanup(cleanup_vm_msync_trials)))             \
	= allocate_vm_msync_trials(countof(vm_msync_trials_values));        \
	append_trials(trials, vm_msync_trials_values, countof(vm_msync_trials_values))

// generate vm_msync_t trials

typedef struct {
	int value;
	const char * name;
} vm_msync_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	vm_msync_trial_t list[];
} vm_msync_trials_t;


#define VM_MSYNC_TRIAL(new_value) \
	(vm_msync_trial_t) {.value = (int)(new_value), .name = "vm_msync_t " #new_value}

static vm_msync_trial_t vm_msync_trials_values[] = {
	VM_MSYNC_TRIAL(0),
	// start valid values
	VM_MSYNC_TRIAL(MS_ASYNC),
	VM_MSYNC_TRIAL(MS_INVALIDATE),
	VM_MSYNC_TRIAL(MS_KILLPAGES),
	VM_MSYNC_TRIAL(MS_DEACTIVATE),
	VM_MSYNC_TRIAL(MS_SYNC),
	VM_MSYNC_TRIAL(MS_ASYNC | MS_INVALIDATE),
	// end valid values
	VM_MSYNC_TRIAL(1u << 5),
	VM_MSYNC_TRIAL(1u << 6),
	VM_MSYNC_TRIAL(1u << 7),
	VM_MSYNC_TRIAL(1u << 8),
	VM_MSYNC_TRIAL(1u << 9),
	VM_MSYNC_TRIAL(1u << 10),
	VM_MSYNC_TRIAL(1u << 11),
	VM_MSYNC_TRIAL(1u << 12),
	VM_MSYNC_TRIAL(1u << 13),
	VM_MSYNC_TRIAL(1u << 14),
	VM_MSYNC_TRIAL(1u << 15),
	VM_MSYNC_TRIAL(1u << 16),
	VM_MSYNC_TRIAL(1u << 17),
	VM_MSYNC_TRIAL(1u << 18),
	VM_MSYNC_TRIAL(1u << 19),
	VM_MSYNC_TRIAL(1u << 20),
	VM_MSYNC_TRIAL(1u << 21),
	VM_MSYNC_TRIAL(1u << 22),
	VM_MSYNC_TRIAL(1u << 23),
	VM_MSYNC_TRIAL(1u << 24),
	VM_MSYNC_TRIAL(1u << 25),
	VM_MSYNC_TRIAL(1u << 26),
	VM_MSYNC_TRIAL(1u << 27),
	VM_MSYNC_TRIAL(1u << 28),
	VM_MSYNC_TRIAL(1u << 29),
	VM_MSYNC_TRIAL(1u << 30),
	VM_MSYNC_TRIAL(1u << 31),
	VM_MSYNC_TRIAL(MS_ASYNC | MS_SYNC),
	VM_MSYNC_TRIAL(0xffffffff),
};

TRIALS_IMPL(vm_msync)

static void __attribute__((used))
cleanup_vm_msync_trials(vm_msync_trials_t **trials)
{
	free_trials(*trials);
}


// allocate advise_t trials, and deallocate it at end of scope
#define SMART_VM_ADVISE_TRIALS()                                           \
	__attribute__((cleanup(cleanup_advise_trials)))                 \
	= allocate_vm_advise_trials(countof(vm_advise_trials_values));        \
	append_trials(trials, vm_advise_trials_values, countof(vm_advise_trials_values))

// generate advise_t trials

typedef struct {
	int value;
	const char * name;
} vm_advise_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	vm_advise_trial_t list[];
} vm_advise_trials_t;


#define ADVISE_TRIAL(new_value) \
	(vm_advise_trial_t) {.value = (int)(new_value), .name = "advise " #new_value}

static vm_advise_trial_t vm_advise_trials_values[] = {
	ADVISE_TRIAL(MADV_NORMAL),
	ADVISE_TRIAL(MADV_RANDOM),
	ADVISE_TRIAL(MADV_SEQUENTIAL),
	ADVISE_TRIAL(MADV_WILLNEED),
	ADVISE_TRIAL(MADV_DONTNEED),
	ADVISE_TRIAL(MADV_FREE),
	ADVISE_TRIAL(MADV_ZERO_WIRED_PAGES),
	ADVISE_TRIAL(MADV_FREE_REUSABLE),
	ADVISE_TRIAL(MADV_FREE_REUSE),
	ADVISE_TRIAL(MADV_CAN_REUSE),
	ADVISE_TRIAL(MADV_PAGEOUT),
	ADVISE_TRIAL(MADV_ZERO),
	// end valid ones
	ADVISE_TRIAL(MADV_ZERO + 1),
	ADVISE_TRIAL(MADV_ZERO + 2),
	ADVISE_TRIAL(0xffffffff),
};

TRIALS_IMPL(vm_advise)

static void __attribute__((used))
cleanup_advise_trials(vm_advise_trials_t **trials)
{
	free_trials(*trials);
}

// allocate machine_attribute_t trials, and deallocate it at end of scope
#define SMART_VM_MACHINE_ATTRIBUTE_TRIALS()                                           \
	__attribute__((cleanup(cleanup_vm_machine_attribute_trials)))                 \
	= allocate_vm_machine_attribute_trials(countof(vm_machine_attribute_trials_values));        \
	append_trials(trials, vm_machine_attribute_trials_values, countof(vm_machine_attribute_trials_values))

// generate advise_t trials

typedef struct {
	vm_machine_attribute_t value;
	const char * name;
} vm_machine_attribute_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	vm_machine_attribute_trial_t list[];
} vm_machine_attribute_trials_t;


#define VM_MACHINE_ATTRIBUTE_TRIAL(new_value) \
	(vm_machine_attribute_trial_t) {.value = (vm_machine_attribute_t)(new_value), .name = "vm_machine_attribute_t " #new_value}

static vm_machine_attribute_trial_t vm_machine_attribute_trials_values[] = {
	VM_MACHINE_ATTRIBUTE_TRIAL(0),
	// start valid ones
	VM_MACHINE_ATTRIBUTE_TRIAL(MATTR_CACHE),
	VM_MACHINE_ATTRIBUTE_TRIAL(MATTR_MIGRATE),
	VM_MACHINE_ATTRIBUTE_TRIAL(MATTR_REPLICATE),
	// end valid ones
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 3),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 4),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 5),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 6),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 7),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 8),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 9),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 10),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 11),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 12),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 13),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 14),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 15),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 16),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 17),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 18),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 19),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 20),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 21),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 22),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 23),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 24),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 25),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 26),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 27),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 28),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 29),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 30),
	VM_MACHINE_ATTRIBUTE_TRIAL(1u << 31),
};

TRIALS_IMPL(vm_machine_attribute)

static void
cleanup_vm_machine_attribute_trials(vm_machine_attribute_trials_t **trials)
{
	free_trials(*trials);
}

// allocate vm_map_kernel_flags trials, and deallocate it at end of scope
#define SMART_VM_MAP_KERNEL_FLAGS_TRIALS()                              \
	__attribute__((cleanup(cleanup_vm_map_kernel_flags_trials)))    \
	= generate_vm_map_kernel_flags_trials()


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

#if KERNEL
#define KERNEL_VM_TAG_TRIAL(new_tag)     \
	(vm_tag_trial_t){ .tag = (vm_tag_t)(new_tag), .name = "vm_tag "#new_tag }

#define VM_TAG_TRIAL KERNEL_VM_TAG_TRIAL
#else
#define USER_VM_TAG_TRIAL(new_tag)      \
	(vm_tag_trial_t){ .tag = (vm_tag_t)0, .name = "vm_tag "#new_tag }

#define VM_TAG_TRIAL USER_VM_TAG_TRIAL
#endif

static vm_tag_trial_t vm_tag_trials_values[] = {
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
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_WRITE | 1u << 23),
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

	// error case coverage in specific subfunctions
	VM_PROT_TRIAL(VM_PROT_READ | MAP_MEM_ONLY | MAP_MEM_USE_DATA_ADDR),
	VM_PROT_TRIAL(VM_PROT_READ | MAP_MEM_ONLY | MAP_MEM_4K_DATA_ADDR),
	VM_PROT_TRIAL(VM_PROT_READ | MAP_MEM_NAMED_CREATE | MAP_MEM_USE_DATA_ADDR),
	VM_PROT_TRIAL(VM_PROT_READ | MAP_MEM_NAMED_CREATE | MAP_MEM_4K_DATA_ADDR),
	VM_PROT_TRIAL(VM_PROT_READ | MAP_MEM_NAMED_CREATE | MAP_MEM_PURGABLE),
	VM_PROT_TRIAL(VM_PROT_NONE | MAP_MEM_VM_SHARE | VM_PROT_IS_MASK),

	// interesting non-error cases for additional test coverage
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_NAMED_CREATE | MAP_MEM_PURGABLE),
	VM_PROT_TRIAL(VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_NAMED_CREATE |
    MAP_MEM_PURGABLE | MAP_MEM_PURGABLE_KERNEL_ONLY),
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


// vm_purgeable_t trial contents.
typedef struct {
	vm_purgable_t value;
	char * name;
} vm_purgeable_trial_t;

#define VM_PURGEABLE_TRIAL(new_value) \
	(vm_purgeable_trial_t) {.value = (vm_purgable_t)(new_value), .name = "vm_purgeable_t " #new_value}

static vm_purgeable_trial_t vm_purgeable_trials_values[] = {
	VM_PURGEABLE_TRIAL(VM_PURGABLE_SET_STATE),
	VM_PURGEABLE_TRIAL(VM_PURGABLE_GET_STATE),
	VM_PURGEABLE_TRIAL(VM_PURGABLE_PURGE_ALL),
	VM_PURGEABLE_TRIAL(VM_PURGABLE_SET_STATE_FROM_KERNEL),
	// end valid values
	VM_PURGEABLE_TRIAL(VM_PURGABLE_SET_STATE_FROM_KERNEL + 1),
	VM_PURGEABLE_TRIAL(VM_PURGABLE_SET_STATE_FROM_KERNEL + 2),
	VM_PURGEABLE_TRIAL(0x12345),
	VM_PURGEABLE_TRIAL(0xffffffff),
};

typedef struct {
	int value;
	char * name;
} vm_purgeable_state_trial_t;

#define VM_PURGEABLE_STATE_TRIAL(new_value) \
	(vm_purgeable_state_trial_t) {.value = (int)(new_value), .name = "state " #new_value}

static vm_purgeable_state_trial_t vm_purgeable_state_trials_values[] = {
	VM_PURGEABLE_STATE_TRIAL(VM_PURGABLE_NO_AGING),
	VM_PURGEABLE_STATE_TRIAL(VM_PURGABLE_DEBUG_EMPTY),
	VM_PURGEABLE_STATE_TRIAL(VM_VOLATILE_GROUP_0),
	VM_PURGEABLE_STATE_TRIAL(VM_VOLATILE_GROUP_7),
	VM_PURGEABLE_STATE_TRIAL(VM_PURGABLE_BEHAVIOR_FIFO),
	VM_PURGEABLE_STATE_TRIAL(VM_PURGABLE_ORDERING_NORMAL),
	VM_PURGEABLE_STATE_TRIAL(VM_PURGABLE_EMPTY),
	VM_PURGEABLE_STATE_TRIAL(VM_PURGABLE_DENY),
	VM_PURGEABLE_STATE_TRIAL(VM_PURGABLE_NONVOLATILE),
	VM_PURGEABLE_STATE_TRIAL(VM_PURGABLE_VOLATILE),
	VM_PURGEABLE_STATE_TRIAL(0x12345),
	VM_PURGEABLE_STATE_TRIAL(0xffffffff),
};

// Trials for vm_purgeable_t and state
typedef struct {
	vm_purgable_t control;
	int state;
	char * name;
} vm_purgeable_and_state_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	vm_purgeable_and_state_trial_t list[];
} vm_purgeable_and_state_trials_t;

TRIALS_IMPL(vm_purgeable_and_state)

#define VM_PURGEABLE_AND_STATE_TRIAL(new_control, new_state, new_name) \
(vm_purgeable_and_state_trial_t){ .control = (vm_purgable_t)(new_control), \
	        .state = (int)(new_state), \
	        .name = new_name,}

vm_purgeable_and_state_trials_t *
generate_vm_purgeable_t_and_state_trials()
{
	const unsigned purgeable_trial_count = countof(vm_purgeable_trials_values);
	const unsigned state_trial_count = countof(vm_purgeable_state_trials_values);
	unsigned num_trials = purgeable_trial_count * state_trial_count;

	vm_purgeable_and_state_trials_t * trials = allocate_vm_purgeable_and_state_trials(num_trials);
	for (size_t i = 0; i < purgeable_trial_count; i++) {
		for (size_t j = 0; j < state_trial_count; j++) {
			vm_purgeable_trial_t control_trial = vm_purgeable_trials_values[i];
			vm_purgeable_state_trial_t state_trial = vm_purgeable_state_trials_values[j];
			char *str;
			kasprintf(&str, "%s, %s", control_trial.name, state_trial.name);
			append_trial(trials, VM_PURGEABLE_AND_STATE_TRIAL(control_trial.value, state_trial.value, str));
		}
	}
	return trials;
}

#define SMART_VM_PURGEABLE_AND_STATE_TRIALS()                           \
	__attribute__((cleanup(cleanup_vm_purgeable_t_and_state_trials))) \
	= generate_vm_purgeable_t_and_state_trials();

static void
cleanup_vm_purgeable_t_and_state_trials(vm_purgeable_and_state_trials_t **trials)
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
	addr_t test_page_size = adjust_page_size();
	if (!offsets) {
		offsets = allocate_offsets(20);
		append_offset(offsets, true, 0);
		append_offset(offsets, true, 1);
		append_offset(offsets, true, 2);
		append_offset(offsets, true, test_page_size - 2);
		append_offset(offsets, true, test_page_size - 1);
		append_offset(offsets, true, test_page_size);
		append_offset(offsets, true, test_page_size + 1);
		append_offset(offsets, true, test_page_size + 2);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size - 2);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size - 1);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size + 1);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size + 2);
		append_offset(offsets, true, -(mach_vm_address_t)2);
		append_offset(offsets, true, -(mach_vm_address_t)1);

		append_offset(offsets, false, 0);
		append_offset(offsets, false, 1);
		append_offset(offsets, false, 2);
		append_offset(offsets, false, test_page_size - 2);
		append_offset(offsets, false, test_page_size - 1);
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
	addr_t test_page_size = adjust_page_size();
	if (!offsets) {
		offsets = allocate_offsets(15);
		append_offset(offsets, true, 0);
		append_offset(offsets, true, 1);
		append_offset(offsets, true, 2);
		append_offset(offsets, true, test_page_size - 2);
		append_offset(offsets, true, test_page_size - 1);
		append_offset(offsets, true, test_page_size);
		append_offset(offsets, true, test_page_size + 1);
		append_offset(offsets, true, test_page_size + 2);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size - 2);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size - 1);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size + 1);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size + 2);
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
	addr_t test_page_size = adjust_page_size();
	if (round_up_page(obj_size, test_page_size) == 0) {
		return false;
	}
	/* in rosetta, PAGE_SIZE is 4K but rounding to 16K also panics */ \
	if (!kern_trialname_generation && isRosetta() && round_up_page(obj_size, KB16) == 0) {
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
	addr_t test_page_size = adjust_page_size();
	if (!offsets) {
		offsets = allocate_offsets(20);
		append_offset(offsets, true, 0);
		append_offset(offsets, true, 1);
		append_offset(offsets, true, 2);
		append_offset(offsets, true, test_page_size - 2);
		append_offset(offsets, true, test_page_size - 1);
		append_offset(offsets, true, test_page_size);
		append_offset(offsets, true, test_page_size + 1);
		append_offset(offsets, true, test_page_size + 2);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size - 2);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size - 1);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size + 1);
		append_offset(offsets, true, -(mach_vm_address_t)test_page_size + 2);
		append_offset(offsets, true, -(mach_vm_address_t)2);
		append_offset(offsets, true, -(mach_vm_address_t)1);
	}
	return offsets;
}

static offset_list_t *
get_ssoo_absolute_and_relative_offsets()
{
	static offset_list_t *offsets;
	addr_t test_page_size = adjust_page_size();
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
		append_offset(offsets, false, test_page_size - 2);
		append_offset(offsets, false, test_page_size - 1);
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


// Trials for start/size/start/size tuples

typedef struct {
	mach_vm_address_t start;
	mach_vm_size_t size;
	mach_vm_address_t second_start;
	mach_vm_size_t second_size;
	bool start_is_absolute;
	bool size_is_absolute;
	bool second_start_is_absolute;
	bool second_size_is_absolute;
	char * name;
} start_size_start_size_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	start_size_start_size_trial_t list[];
} start_size_start_size_trials_t;

TRIALS_IMPL(start_size_start_size)

#define START_SIZE_START_SIZE_TRIAL(new_start, new_size, new_second_start, new_second_size, new_start_is_absolute, \
	    new_size_is_absolute, new_second_start_is_absolute, new_second_size_is_absolute, new_name) \
(start_size_start_size_trial_t){ .start = (mach_vm_address_t)(new_start), \
	        .size = (mach_vm_size_t)(new_size), \
	        .second_start = (mach_vm_address_t)(new_second_start), \
	        .second_size = (mach_vm_size_t)(new_second_size), \
	        .start_is_absolute = (bool)(new_start_is_absolute), \
	        .size_is_absolute = (bool)(new_size_is_absolute), \
	        .second_start_is_absolute = (bool)(new_second_start_is_absolute), \
	        .second_size_is_absolute = (bool)(new_second_size_is_absolute),\
	        .name = new_name,}

static start_size_start_size_trial_t __attribute__((overloadable, used))
slide_trial(start_size_start_size_trial_t trial, mach_vm_address_t slide, mach_vm_address_t second_slide)
{
	start_size_start_size_trial_t result = trial;

	if (!trial.start_is_absolute) {
		result.start += slide;
		if (!trial.size_is_absolute) {
			result.size -= slide;
		}
	}
	if (!trial.second_start_is_absolute) {
		result.second_start += second_slide;
		if (!trial.second_size_is_absolute) {
			result.second_size -= second_slide;
		}
	}
	return result;
}

start_size_start_size_trials_t *
generate_start_size_start_size_trials()
{
	/*
	 * Reuse the starts/sizes from start/size/offset/object
	 */
	const offset_list_t *start_offsets        = get_ssoo_absolute_and_relative_offsets();
	const offset_list_t *size_offsets         = get_ssoo_absolute_and_relative_offsets();
	const offset_list_t *second_start_offsets = get_ssoo_absolute_and_relative_offsets();
	const offset_list_t *second_size_offsets  = get_ssoo_absolute_and_relative_offsets();

	unsigned num_trials = start_offsets->count * size_offsets->count
	    * second_start_offsets->count * second_start_offsets->count;

	start_size_start_size_trials_t * trials = allocate_start_size_start_size_trials(num_trials);
	for (size_t a = 0; a < start_offsets->count; a++) {
		for (size_t b = 0; b < size_offsets->count; b++) {
			for (size_t c = 0; c < second_start_offsets->count; c++) {
				for (size_t d = 0; d < second_size_offsets->count; d++) {
					bool start_is_absolute = start_offsets->list[a].is_absolute;
					bool size_is_absolute = size_offsets->list[b].is_absolute;
					bool second_start_is_absolute = second_start_offsets->list[c].is_absolute;
					bool second_size_is_absolute = second_size_offsets->list[d].is_absolute;
					mach_vm_address_t start = start_offsets->list[a].offset;
					mach_vm_size_t size = size_offsets->list[b].offset;
					mach_vm_address_t second_start = second_start_offsets->list[c].offset;
					mach_vm_size_t second_size = second_size_offsets->list[d].offset;

					char *str;
					kasprintf(&str, "start: %s0x%llx, size: %s0x%llx, second_start: %s0x%llx, second_size: %s0x%llx",
					    start_is_absolute ? "" : "base+", start,
					    size_is_absolute ? "" :"-start+", size,
					    second_start_is_absolute ? "" : "base+", second_start,
					    second_size_is_absolute ? "" : "-start+", second_size);
					append_trial(trials, START_SIZE_START_SIZE_TRIAL(start, size, second_start, second_size,
					    start_is_absolute, size_is_absolute,
					    second_start_is_absolute, second_size_is_absolute, str));
				}
			}
		}
	}
	return trials;
}

#define SMART_START_SIZE_START_SIZE_TRIALS()                                            \
	__attribute__((cleanup(cleanup_start_size_start_size_trials)))                  \
	= generate_start_size_start_size_trials();

static void __attribute__((used))
cleanup_start_size_start_size_trials(start_size_start_size_trials_t **trials)
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

#if !KERNEL
// shared_file_np / shared_file_mapping_slide_np tests

// copied from bsd/vm/vm_unix.c
#define _SR_FILE_MAPPINGS_MAX_FILES     256
#define SFM_MAX (_SR_FILE_MAPPINGS_MAX_FILES * 8)

// From Rosetta dyld
#define kNumSharedCacheMappings 4
#define kMaxSubcaches 16

typedef struct {
	uint32_t files_count;
	struct shared_file_np *files;
	char *name;
} shared_file_np_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	shared_file_np_trial_t list[];
} shared_file_np_trials_t;

TRIALS_IMPL(shared_file_np)

#define SHARED_FILE_NP_TRIAL(new_files_count, new_files, new_name) \
(shared_file_np_trial_t){ .files_count = (uint32_t)(new_files_count), \
	    .files = (struct shared_file_np *)(new_files), \
	    .name = "files_count="#new_files_count new_name }

struct shared_file_np *
alloc_shared_file_np(uint32_t files_count)
{
	struct shared_file_np *files;
#if KERNEL
	files = kalloc_type(struct shared_file_np, files_count, Z_WAITOK | Z_ZERO);
#else
	files = calloc(files_count, sizeof(struct shared_file_np));
#endif
	return files;
}

void
free_shared_file_np(shared_file_np_trial_t *trial)
{
#if KERNEL
	// some trials have files_count > 0 but null files.
	if (trial->files) {
		kfree_type(struct shared_file_np, trial->files_count, trial->files);
	}
#else
	free(trial->files);
#endif
}

static int get_fd();

shared_file_np_trials_t *
get_shared_file_np_trials(uint64_t dyld_fd)
{
	struct shared_file_np * files = NULL;
	shared_file_np_trials_t *trials = allocate_shared_file_np_trials(11);
	append_trial(trials, SHARED_FILE_NP_TRIAL(0, NULL, " (NULL files)"));
	append_trial(trials, SHARED_FILE_NP_TRIAL(1, NULL, " (NULL files)"));
	append_trial(trials, SHARED_FILE_NP_TRIAL(_SR_FILE_MAPPINGS_MAX_FILES - 1, NULL, " (NULL files)"));
	append_trial(trials, SHARED_FILE_NP_TRIAL(_SR_FILE_MAPPINGS_MAX_FILES, NULL, " (NULL files)"));
	append_trial(trials, SHARED_FILE_NP_TRIAL(_SR_FILE_MAPPINGS_MAX_FILES + 1, NULL, " (NULL files)"));
	files = alloc_shared_file_np(1);
	append_trial(trials, SHARED_FILE_NP_TRIAL(1, files, ""));
	files = alloc_shared_file_np(_SR_FILE_MAPPINGS_MAX_FILES - 1);
	append_trial(trials, SHARED_FILE_NP_TRIAL(_SR_FILE_MAPPINGS_MAX_FILES - 1, files, ""));
	files = alloc_shared_file_np(_SR_FILE_MAPPINGS_MAX_FILES);
	append_trial(trials, SHARED_FILE_NP_TRIAL(_SR_FILE_MAPPINGS_MAX_FILES, files, ""));
	files = alloc_shared_file_np(_SR_FILE_MAPPINGS_MAX_FILES + 1);
	append_trial(trials, SHARED_FILE_NP_TRIAL(_SR_FILE_MAPPINGS_MAX_FILES + 1, files, ""));
	files = alloc_shared_file_np(1);
	files->sf_fd = get_fd();
	files->sf_slide = 4096;
	files->sf_mappings_count = 1;
	append_trial(trials, SHARED_FILE_NP_TRIAL(1, files, " non-zero shared_file_np"));
	files = alloc_shared_file_np(2);
	files[0].sf_fd = (int)dyld_fd;
	files[0].sf_mappings_count = 1;
	files[1].sf_fd = files[0].sf_fd;
	files[1].sf_mappings_count = 4;
	append_trial(trials, SHARED_FILE_NP_TRIAL(2, files, " checks shared_file_np"));
	return trials;
}

static void
cleanup_shared_file_np_trials(shared_file_np_trials_t **trials)
{
	for (size_t i = 0; i < (*trials)->count; i++) {
		free_shared_file_np(&(*trials)->list[i]);
	}
	free_trials(*trials);
}

typedef struct {
	uint32_t mappings_count;
	struct shared_file_mapping_slide_np *mappings;
	char *name;
} shared_file_mapping_slide_np_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	shared_file_mapping_slide_np_trial_t list[];
} shared_file_mapping_slide_np_trials_t;

TRIALS_IMPL(shared_file_mapping_slide_np)

#define SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(new_mappings_count, new_mappings, new_name) \
(shared_file_mapping_slide_np_trial_t){ .mappings_count = (uint32_t)(new_mappings_count), \
	    .mappings = (struct shared_file_mapping_slide_np *)(new_mappings), \
	    .name = "mappings_count="#new_mappings_count new_name }

struct shared_file_mapping_slide_np *
alloc_shared_file_mapping_slide_np(uint32_t mappings_count)
{
	struct shared_file_mapping_slide_np *mappings;
#if KERNEL
	mappings = kalloc_type(struct shared_file_mapping_slide_np, mappings_count, Z_WAITOK | Z_ZERO);
#else
	mappings = calloc(mappings_count, sizeof(struct shared_file_mapping_slide_np));
#endif
	return mappings;
}

void
free_shared_file_mapping_slide_np(shared_file_mapping_slide_np_trial_t *trial)
{
#if KERNEL
	// some trials have files_count > 0 but null files.
	if (trial->mappings) {
		kfree_type(struct shared_file_mapping_slide_np, trial->mappings_count, trial->mappings);
	}
#else
	free(trial->mappings);
#endif
}

typedef enum { MP_NORMAL = 0, MP_ADDR_SIZE = 1, MP_OFFSET_SIZE, MP_PROTS } mapping_slide_np_test_style_t;

static inline struct shared_file_mapping_slide_np *
alloc_and_fill_shared_file_mappings(uint32_t num_mappings, mapping_slide_np_test_style_t style)
{
	assert(num_mappings > 0);
	struct shared_file_mapping_slide_np *mappings = alloc_shared_file_mapping_slide_np(num_mappings);

	// Checks happen in a for-loop so is desirable to differentiate the first mapping.
	switch (style) {
	case MP_NORMAL:
		mappings[0].sms_slide_size = KB4;
		mappings[0].sms_slide_start = KB4;
		mappings[0].sms_max_prot = VM_PROT_DEFAULT;
		mappings[0].sms_init_prot = VM_PROT_DEFAULT;
		break;
	case MP_ADDR_SIZE:
		mappings[0].sms_address = 1;
		mappings[0].sms_size = UINT64_MAX;
		mappings[0].sms_file_offset = 0;
		mappings[0].sms_slide_size = KB4;
		mappings[0].sms_slide_start = KB4;
		mappings[0].sms_max_prot = VM_PROT_DEFAULT;
		mappings[0].sms_init_prot = VM_PROT_DEFAULT;
		break;
	case MP_OFFSET_SIZE:
		mappings[0].sms_size = 0;
		mappings[0].sms_file_offset = UINT64_MAX;
		mappings[0].sms_slide_size = KB4;
		mappings[0].sms_slide_start = KB4;
		mappings[0].sms_max_prot = VM_PROT_DEFAULT;
		mappings[0].sms_init_prot = VM_PROT_DEFAULT;
		break;
	case MP_PROTS:
		mappings[0].sms_slide_size = KB4;
		mappings[0].sms_slide_start = KB4;
		mappings[0].sms_max_prot = VM_PROT_DEFAULT;
		mappings[0].sms_init_prot = INT_MAX;
		break;
	default:
		assert(0);
		break;
	}

	for (size_t idx = 1; idx < num_mappings; idx++) {
		size_t i = idx % 4;
		switch (i) {
		case 0:
			mappings[idx].sms_slide_size = KB4;
			mappings[idx].sms_slide_start = KB4;
			mappings[idx].sms_max_prot = VM_PROT_DEFAULT;
			mappings[idx].sms_init_prot = VM_PROT_DEFAULT;
			break;
		case 1:
			mappings[idx].sms_slide_size = KB4;
			mappings[idx].sms_slide_start = UINT64_MAX;
			mappings[idx].sms_max_prot = VM_PROT_DEFAULT;
			mappings[idx].sms_init_prot = VM_PROT_DEFAULT;
			break;
		case 2:
			mappings[idx].sms_slide_size = 0;
			mappings[idx].sms_slide_start = UINT64_MAX;
			mappings[idx].sms_max_prot = VM_PROT_DEFAULT;
			mappings[idx].sms_init_prot = INT_MAX;
			break;
		case 3:
			mappings[idx].sms_slide_size = KB4;
			mappings[idx].sms_slide_start = 0;
			mappings[idx].sms_max_prot = INT_MAX;
			mappings[idx].sms_init_prot = VM_PROT_DEFAULT;
			break;
		default:
			assert(0);
			break;
		}
	}
	return mappings;
}

shared_file_mapping_slide_np_trials_t*
get_shared_file_mapping_slide_np_trials(void)
{
	struct shared_file_mapping_slide_np *mappings = NULL;
	shared_file_mapping_slide_np_trials_t *trials = allocate_shared_file_mapping_slide_np_trials(14);
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(0, NULL, " (NULL mappings)"));
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(1, NULL, " (NULL mappings)"));
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(SFM_MAX - 1, NULL, " (NULL mappings)"));
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(SFM_MAX, NULL, " (NULL mappings)"));
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(SFM_MAX + 1, NULL, " (NULL mappings)"));
	mappings = alloc_and_fill_shared_file_mappings(1, MP_NORMAL);
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(1, mappings, " (normal)"));
	mappings = alloc_and_fill_shared_file_mappings(1, MP_ADDR_SIZE);
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(1, mappings, " (sms_address+sms_size check)"));
	mappings = alloc_and_fill_shared_file_mappings(1, MP_OFFSET_SIZE);
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(1, mappings, " (sms_file_offset+sms_size check)"));
	mappings = alloc_and_fill_shared_file_mappings(1, MP_PROTS);
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(1, mappings, " (sms_init_prot check)"));
	mappings = alloc_and_fill_shared_file_mappings(SFM_MAX - 1, MP_NORMAL);
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(SFM_MAX - 1, mappings, ""));
	mappings = alloc_and_fill_shared_file_mappings(SFM_MAX, MP_NORMAL);
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(SFM_MAX, mappings, ""));
	mappings = alloc_and_fill_shared_file_mappings(SFM_MAX + 1, MP_NORMAL);
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(SFM_MAX + 1, mappings, ""));
	mappings = alloc_and_fill_shared_file_mappings(kNumSharedCacheMappings, MP_NORMAL);
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(kNumSharedCacheMappings, mappings, ""));
	mappings = alloc_and_fill_shared_file_mappings(2 * kNumSharedCacheMappings, MP_NORMAL);
	append_trial(trials, SHARED_FILE_MAPPING_SLIDE_NP_TRIAL(2 * kNumSharedCacheMappings, mappings, ""));

	return trials;
}

static void
cleanup_shared_file_mapping_slide_np_trials(shared_file_mapping_slide_np_trials_t **trials)
{
	for (size_t i = 0; i < (*trials)->count; i++) {
		free_shared_file_mapping_slide_np(&(*trials)->list[i]);
	}
	free_trials(*trials);
}

typedef struct {
	uint32_t files_count;
	struct shared_file_np *files;
	uint32_t mappings_count;
	struct shared_file_mapping_slide_np *mappings;
	char *name;
} shared_region_map_and_slide_2_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	shared_file_np_trials_t *shared_files_trials;
	shared_file_mapping_slide_np_trials_t *shared_mappings_trials;
	shared_region_map_and_slide_2_trial_t list[];
} shared_region_map_and_slide_2_trials_t;

TRIALS_IMPL(shared_region_map_and_slide_2)

#define SHARED_REGION_MAP_AND_SLIDE_2_TRIAL(new_files_count, new_files, new_mappings_count, new_mappings, new_name) \
(shared_region_map_and_slide_2_trial_t){ .files_count = (uint32_t)(new_files_count), \
	    .files = (struct shared_file_np *)(new_files), \
	    .mappings_count = (uint32_t)(new_mappings_count), \
	    .mappings = (struct shared_file_mapping_slide_np *)(new_mappings), \
	    .name = new_name }

shared_region_map_and_slide_2_trials_t *
generate_shared_region_map_and_slide_2_trials(uint64_t dyld_fd)
{
	shared_file_np_trials_t *shared_files = get_shared_file_np_trials(dyld_fd);
	shared_file_mapping_slide_np_trials_t *shared_mappings = get_shared_file_mapping_slide_np_trials();
	unsigned num_trials = shared_files->count * shared_mappings->count;
	shared_region_map_and_slide_2_trials_t *trials = allocate_shared_region_map_and_slide_2_trials(num_trials);
	trials->shared_files_trials = shared_files;
	trials->shared_mappings_trials = shared_mappings;
	for (size_t i = 0; i < shared_files->count; i++) {
		for (size_t j = 0; j < shared_mappings->count; j++) {
			char *buf;
			shared_file_np_trial_t shared_file = shared_files->list[i];
			shared_file_mapping_slide_np_trial_t shared_mapping = shared_mappings->list[j];
			kasprintf(&buf, "%s, %s", shared_file.name, shared_mapping.name);
			append_trial(trials, SHARED_REGION_MAP_AND_SLIDE_2_TRIAL(shared_file.files_count, shared_file.files, shared_mapping.mappings_count, shared_mapping.mappings, buf));
		}
	}
	return trials;
}

#define SMART_SHARED_REGION_MAP_AND_SLIDE_2_TRIALS(dyld_fd)    \
	__attribute__((cleanup(cleanup_shared_region_map_and_slide_2_trials))) \
	= generate_shared_region_map_and_slide_2_trials(dyld_fd);

static void __attribute__((used))
cleanup_shared_region_map_and_slide_2_trials(shared_region_map_and_slide_2_trials_t **trials)
{
	for (size_t i = 0; i < (*trials)->count; i++) {
		kfree_str((*trials)->list[i].name);
	}
	cleanup_shared_file_np_trials(&(*trials)->shared_files_trials);
	cleanup_shared_file_mapping_slide_np_trials(&(*trials)->shared_mappings_trials);
	free_trials(*trials);
}
#endif // !KERNEL

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

// PPL is inefficient at deallocations of very large address ranges.
// Skip those trials to avoid test timeouts.
// We assume that tests on other devices will cover any testing gaps.
static inline bool
dealloc_would_time_out(
	mach_vm_address_t addr __unused,
	mach_vm_size_t size __unused,
	vm_map_t map __unused)
{
#if CONFIG_SPTM
	/* not PPL - okay */
	return false;
#elif !(__ARM_42BIT_PA_SPACE__ || ARM_LARGE_MEMORY)
	/* PPL but small pmap address space - okay */
	return false;
#else
	/*
	 * PPL with large pmap address space - bad
	 * Pre-empt trials of very large allocations.
	 */
	return size > 0x8000000000;
#endif
}

#if !KERNEL

// SMART_MAP is mach_task_self() in userspace and a new empty map in kernel
#define SMART_MAP = mach_task_self()

// CURRENT_MAP is mach_task_self() in userspace and current_map() in kernel
#define CURRENT_MAP = mach_task_self()

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

	/*
	 * Normally, we would vm_map_setup a task's map, but since we're breaking the assumed
	 * 1:1 correspondence between map and task here, we must manually set up the map's
	 * back pointer, without repeating any one-time task setup (e.g. registering reclaim
	 * buffers)
	 */
	map->owning_task = current_task();

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

// This map has a map_offset that matches what a user would get. This allows
// vm_map_user_ranges to work properly when tested from the kernel
#define SMART_RANGE_MAP                                                       \
	__attribute__((cleanup(cleanup_map))) = create_map(0, vm_compute_max_offset(true))

#define CURRENT_MAP = current_map()

#endif

// Allocate with an address hint.
static kern_return_t
allocate_after(
	MAP_T               map,
	mach_vm_address_t  *address,
	mach_vm_size_t      size,
	mach_vm_size_t      align_mask,
	int                 additional_map_flags)
{
	return mach_vm_map(map, address, size, align_mask,
	           VM_FLAGS_ANYWHERE | additional_map_flags, 0, 0, 0,
	           VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
}

static inline mach_vm_address_t
default_allocation_address_hint(void)
{
	/*
	 * Try to allocate after address 2 GB. It is important in
	 * in-kernel tests of empty maps to avoid addresses near 0 and ~0.
	 */
	return 2ull * 1024 * 1024 * 1024;
}

// allocate a purgeable VM region with size and permissions
// and deallocate it at end of scope
#define SMART_ALLOCATE_PURGEABLE_VM(map, size, perm)                              \
    __attribute__((cleanup(cleanup_allocation))) = create_allocation(map, size, 0, perm, false, VM_FLAGS_PURGABLE)

// allocate a VM region with size and permissions
// and deallocate it at end of scope
#define SMART_ALLOCATE_VM(map, size, perm)                              \
    __attribute__((cleanup(cleanup_allocation))) = create_allocation(map, size, 0, perm, false, 0)

// allocate a VM region with size and permissions
// and an address hint to allocate after
// and deallocate it at end of scope
#define SMART_ALLOCATE_VM_AFTER(map, address_hint, size, perm)          \
    __attribute__((cleanup(cleanup_allocation))) = create_allocation_after(map, address_hint, size, 0, perm, false, 0)

// allocate a VM region with size and permissions and alignment
// and deallocate it at end of scope
#define SMART_ALLOCATE_ALIGNED_VM(map, size, align_mask, perm)          \
    __attribute__((cleanup(cleanup_allocation))) = create_allocation(map, size, align_mask, perm, false, 0)

// allocate a VM region with size and permissions
// and deallocate it at end of scope
// If no such region could be allocated, return {.addr = 0}
#define SMART_TRY_ALLOCATE_VM(map, size, perm)                              \
    __attribute__((cleanup(cleanup_allocation))) = create_allocation(map, size, 0, perm, true, 0)

// a VM allocation with unallocated pages around it
typedef struct {
	MAP_T map;
	addr_t guard_size;
	addr_t guard_prefix;        // guard_size bytes
	addr_t unallocated_prefix;  // guard_size bytes
	addr_t addr;
	addr_t size;
	addr_t unallocated_suffix;  // guard_size bytes
	addr_t guard_suffix;        // guard_size bytes
} allocation_t;

static allocation_t
create_allocation_after(MAP_T new_map, mach_vm_address_t address_hint, mach_vm_address_t new_size, mach_vm_size_t align_mask,
    vm_prot_t perm, bool allow_failure, int additional_map_flags)
{
	// allocations in address order:
	// 16K guard_prefix (allocated, prot none)
	// 16K unallocated_prefix (unallocated)
	// N   addr..addr+size
	// 16K unallocated_suffix (unallocated)
	// 16K guard_suffix (allocated, prot none)

	// allocate new_size + 4 * 16K bytes
	// then carve it up into our regions

	allocation_t result;

	result.map = new_map;

	// this implementation only works with some alignment values
	assert(align_mask == 0 || align_mask == KB4 - 1 || align_mask == KB16 - 1);

	result.guard_size = KB16;
	result.size = round_up_page(new_size, KB16);
	if (result.size == 0 && allow_failure) {
		return (allocation_t){new_map, 0, 0, 0, 0, 0, 0, 0};
	}
	assert(result.size != 0);

	mach_vm_address_t allocated_base = address_hint;
	mach_vm_size_t allocated_size = result.size;
	if (__builtin_add_overflow(result.size, result.guard_size * 4, &allocated_size)) {
		if (allow_failure) {
			return (allocation_t){new_map, 0, 0, 0, 0, 0, 0, 0};
		} else {
			assert(false);
		}
	}

	kern_return_t kr;
	kr = allocate_after(result.map, &allocated_base, allocated_size,
	    align_mask, additional_map_flags);
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

static allocation_t
create_allocation(MAP_T new_map, mach_vm_address_t new_size, mach_vm_size_t align_mask,
    vm_prot_t perm, bool allow_failure, int additional_map_flags)
{
	mach_vm_address_t address_hint = default_allocation_address_hint();
	return create_allocation_after(new_map, address_hint, new_size, align_mask, perm, allow_failure, additional_map_flags);
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
// and an address hint to allocate above
// and deallocate it at end of scope
#define SMART_UNALLOCATE_VM_AFTER(map, address_hint, size)              \
	__attribute__((cleanup(cleanup_unallocation))) = create_unallocation_after(map, address_hint, size, false)

// unallocate a VM region with size
// and deallocate it at end of scope
// If no such region could be allocated, return {.addr = 0}
#define SMART_TRY_UNALLOCATE_VM(map, size)                                  \
	__attribute__((cleanup(cleanup_unallocation))) = create_unallocation(map, size, true)

// a VM space with allocated pages around it
typedef struct {
	MAP_T map;
	addr_t guard_size;
	addr_t guard_prefix;  // 16K
	addr_t addr;
	addr_t size;
	addr_t guard_suffix;  // 16K
} unallocation_t;

static unallocation_t __attribute__((overloadable))
create_unallocation_after(MAP_T new_map, mach_vm_address_t address_hint, mach_vm_address_t new_size, bool allow_failure)
{
	// allocations in address order:
	// 16K guard_prefix (allocated, prot none)
	// N   addr..addr+size (unallocated)
	// 16K guard_suffix (allocated, prot none)

	// allocate new_size + 2 * 16K bytes
	// then carve it up into our regions

	unallocation_t result;

	result.map = new_map;

	result.guard_size = KB16;
	result.size = round_up_page(new_size, KB16);
	if (result.size == 0 && allow_failure) {
		return (unallocation_t){new_map, 0, 0, 0, 0, 0};
	}
	assert(result.size != 0);

	mach_vm_address_t allocated_base = address_hint;
	mach_vm_size_t allocated_size = result.size;
	if (__builtin_add_overflow(result.size, result.guard_size * 2, &allocated_size)) {
		if (allow_failure) {
			return (unallocation_t){new_map, 0, 0, 0, 0, 0};
		} else {
			assert(false);
		}
	}
	kern_return_t kr;
	kr = allocate_after(result.map, &allocated_base, allocated_size, 0, 0);
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
create_unallocation(MAP_T new_map, mach_vm_address_t new_size, bool allow_failure)
{
	mach_vm_address_t address_hint = default_allocation_address_hint();
	return create_unallocation_after(new_map, address_hint, new_size, allow_failure);
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

// TODO: re-enable deferred reclaim tests (rdar://136157720)
#if 0
// vm_deferred_reclamation_buffer_init_internal tests
typedef struct {
	task_t task;
	mach_vm_address_t address;
	mach_vm_reclaim_count_t initial_capacity;
	mach_vm_reclaim_count_t max_capacity;
	char *name;
} reclamation_buffer_init_trial_t;

typedef struct {
	unsigned count;
	unsigned capacity;
	reclamation_buffer_init_trial_t list[];
} reclamation_buffer_init_trials_t;

TRIALS_IMPL(reclamation_buffer_init)

#define RECLAMATION_BUFFER_INIT_TRIAL(new_task, new_address, new_initial_capacity, new_max_capacity, new_name) \
(reclamation_buffer_init_trial_t){ .task = (task_t)(new_task), \
	    .address = (mach_vm_address_t)(new_address), \
	    .initial_capacity= (mach_vm_reclaim_count_t)(new_initial_capacity), \
	    .max_capacity= (mach_vm_reclaim_count_t)(new_max_capacity), \
	    .name = new_name }

#define RECLAMATION_BUFFER_INIT_EXTRA_TRIALS   7

reclamation_buffer_init_trials_t *
generate_reclamation_buffer_init_trials(void)
{
	MAP_T map SMART_MAP;
	allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	addr_trials_t *addr_trials SMART_ADDR_TRIALS(0);
	reclamation_buffer_init_trials_t *trials = allocate_reclamation_buffer_init_trials(addr_trials->count + RECLAMATION_BUFFER_INIT_EXTRA_TRIALS);
	for (size_t i = 0; i < addr_trials->count; i++) {
		char *buf;
		mach_vm_size_t size = i * 512;
		kasprintf(&buf, "%s, size: 0x%llu", addr_trials->list[i].name, size);
		append_trial(trials, RECLAMATION_BUFFER_INIT_TRIAL(current_task(), addr_trials->list[i].addr, size, size, buf));
	}

	append_trial(trials, RECLAMATION_BUFFER_INIT_TRIAL(current_task(), base.addr, 0, 0, "size: 0"));
	append_trial(trials, RECLAMATION_BUFFER_INIT_TRIAL(current_task(), base.addr, VM_RECLAIM_MAX_CAPACITY - 1, VM_RECLAIM_MAX_CAPACITY - 1, "size: MAX - 1"));
	append_trial(trials, RECLAMATION_BUFFER_INIT_TRIAL(current_task(), base.addr, VM_RECLAIM_MAX_CAPACITY, VM_RECLAIM_MAX_CAPACITY, "size: MAX"));
	append_trial(trials, RECLAMATION_BUFFER_INIT_TRIAL(current_task(), base.addr, UINT32_MAX, UINT32_MAX, "size: UINT32_MAX"));
	append_trial(trials, RECLAMATION_BUFFER_INIT_TRIAL(current_task(), base.addr, 2, 1, "size: max < initial"));
	append_trial(trials, RECLAMATION_BUFFER_INIT_TRIAL(NULL, NULL, 0, 0, "null task, null address, size: 0"));
	append_trial(trials, RECLAMATION_BUFFER_INIT_TRIAL(current_task(), NULL, 0, 0, "null address, size: 0"));
	append_trial(trials, RECLAMATION_BUFFER_INIT_TRIAL(current_task(), base.addr, 1024, 1024, "valid arguments to test KERN_NOT_SUPPORTED"));

	return trials;
}

#define SMART_RECLAMATION_BUFFER_INIT_TRIALS()    \
	__attribute__((cleanup(cleanup_reclamation_buffer_init_trials))) \
	= generate_reclamation_buffer_init_trials();

static void __attribute__((used))
cleanup_reclamation_buffer_init_trials(reclamation_buffer_init_trials_t **trials)
{
	for (size_t i = 0; i < (*trials)->count - RECLAMATION_BUFFER_INIT_EXTRA_TRIALS; i++) {
		kfree_str((*trials)->list[i].name);
	}
	free_trials(*trials);
}

static kern_return_t
call_mach_vm_deferred_reclamation_buffer_init(task_t task, mach_vm_address_t address, mach_vm_reclaim_count_t initial_capacity, mach_vm_reclaim_count_t max_capacity)
{
	kern_return_t kr = 0;
	mach_vm_address_t saved_address = address;
	if (task && max_capacity > 0 && address == 0) {
		// prevent assert3u(*address, !=, 0)
		return PANIC;
	}

	kr = mach_vm_deferred_reclamation_buffer_allocate(task, &address, initial_capacity, max_capacity);

	//Out-param validation, failure shouldn't change inout address.
	if (kr != KERN_SUCCESS && saved_address != address) {
		kr = OUT_PARAM_BAD;
	}
	if (kr == KERN_SUCCESS && saved_address == address) {
		kr = OUT_PARAM_BAD;
	}

	return kr;
}
#endif // 0


// mach_vm_remap_external/vm_remap_external/vm32_remap/mach_vm_remap_new_external infra
// mach_vm_remap/mach_vm_remap_new_kernel infra

/*
 * This comment describes the testing approach that was fleshed out through
 * writing the tests for the map family of functions, and more fully realized
 * for the remap family of functions.
 *
 * This method attempts to radically minimize code reuse, at the expense of
 * decreased navigability (cmd+click is unlikely to work for you for this code)
 * and increased upfront costs for understanding this code. Maintainability
 * should be better in most cases: if a fix needs to happen, it can be
 * implemented in the right place once and doesn’t need to be copy-and-pasted
 * in multiple duplicated functions. There may however be cases where the
 * change you want to make doesn’t fit the spirit of this approach (for
 * instance changing the behavior of the test for only one function in the
 * family).
 *
 * The framework is built around the idea that there are three types of
 * parameters:
 * 1. Parameters that will be fixed for all calls to the function (e.g. some
 *    uncommon type specific to the function that doesn’t impact the input
 *    validation flow)
 * 2. Parameters that cause input validation to change significantly (typically
 *    flags, e.g. fixed vs anywhere). For those we basically want to treat
 *    different values of the flags as calling into different functions (for
 *    the purpose of input validation).
 * 3. Parameters that can be tested. For every test this is further broken down
 *    into 2 subtypes:
 *        A. Parameters being iterated over during the test (e.g. start+size)
 *        B. Parameters that should stay fixed during this test (e.g. pick a
 *           sane value of prot and pass that same value for all values of
 *           start/size)
 *
 * Often, many functions have very similar signatures (they are in the same
 * function family). We want to avoid copy/pasting tests for each function in
 * the family.
 *
 * Here is the flow used for the remap family of functions:
 * 1. Typedef a function type with shared parameters (see remap_fn_t)
 * 2. Define function wrappers that fit the above typedef for each function
 *    in the family (see e.g. mach_vm_remap_new_kernel_wrapped). These might
 *    set values for “type 1” params.
 * 3. Define “helper” functions that take in parameters of types 2 and 3.A.,
 *    and call the wrapper, filling in type 3.B. params. See, e.g.,
 *    help_call_remap_fn__src_size. For remap, all helpers can easily be
 *    implemented as a single call to a core helper function
 *    help_call_remap_fn__src_size_etc.
 * 4. Define generic “caller” functions that take in a wrapper and parameters
 *    of type 3.A. and call the helper. Macros are used to mass implement these
 *    for all values of type 2 parameters and for all functions in the family.
 *    See, e.g., `IMPL_FROM_HELPER(dst_size);`.
 * 5. Specialize the above "caller" functions for each wrapper in the family,
 *    again using macros. See `#define IMPL(remap_fn)` and its uses below.
 *    This results in a number of specialized caller functions that is the
 *    product of the number of functions in the family by the number of
 *    variants induced by type 2 parameters.
 * 6. Use macros to call test harnesses on caller functions en masse at test
 *    time for all functions. See the call sites in `vm_parameter_validation.c`
 *    e.g. `RUN_ALL(mach_vm_remap_new_user, , mach_vm_remap_new);`.
 */

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
	if (dealloc_would_time_out(*target_address, size, target_task)) {
		return ACCEPTABLE;
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
	if (dealloc_would_time_out(*target_address, size, target_task)) {
		return ACCEPTABLE;
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
	/* ...and the allocation has a specified minimum alignment */   \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_allocated_aligned_start_size(NAME ## mach_with_start_size_fn fn, T align_mask, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_ALIGNED_VM(map, TEST_ALLOC_SIZE, align_mask, VM_PROT_DEFAULT); \
	        start_size_trials_t *trials SMART_START_SIZE_TRIALS(base.addr); \
	        results_t *results = alloc_results(testname, eSMART_START_SIZE_TRIALS, base.addr, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                T start = (T)trials->list[i].start;             \
	                T size = (T)trials->list[i].size;               \
	                kern_return_t ret = fn(map, start, size);       \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
                                                                        \
	/* ...and the allocation gets default alignment */              \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_allocated_start_size(NAME ## mach_with_start_size_fn fn, const char *testname) \
	{                                                               \
	        return test_ ## NAME ## mach_with_allocated_aligned_start_size(fn, 0, testname); \
	}                                                               \
                                                                        \
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
	        uint64_t trial_args[TRIALSARGUMENTS_SIZE] = {base.addr, obj_size}; \
	        results_t *results = alloc_results(testname, eSMART_ADDR_TRIALS, trial_args, TRIALSARGUMENTS_SIZE, trials->count+1); \
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
	        results_t *results = alloc_results(testname, eSMART_ADDR_TRIALS, base.addr, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                T addr = (T)trials->list[i].addr;               \
	                kern_return_t ret = fn(map, addr);              \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_allocated_purgeable_addr(NAME ## mach_with_addr_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_PURGEABLE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        addr_trials_t *trials SMART_ADDR_TRIALS(base.addr);     \
	        results_t *results = alloc_results(testname, eSMART_ADDR_TRIALS, base.addr, trials->count); \
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
	        results_t *results = alloc_results(testname, eSMART_SIZE_TRIALS, trials->count); \
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
	test_ ## NAME ## mach_with_allocated_start_size_offset_object(NAME ## mach_with_start_size_offset_object_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        start_size_offset_object_trials_t *trials SMART_START_SIZE_OFFSET_OBJECT_TRIALS(); \
	        results_t *results = alloc_results(testname, eSMART_START_SIZE_OFFSET_OBJECT_TRIALS, trials->count); \
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
	test_ ## NAME ## mach_with_allocated_start_size_offset(NAME ## mach_with_start_size_offset_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        start_size_offset_trials_t *trials SMART_START_SIZE_OFFSET_TRIALS(); \
	        results_t *results = alloc_results(testname, eSMART_START_SIZE_OFFSET_TRIALS, trials->count); \
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
	        results_t *results = alloc_results(testname, eSMART_MMAP_FLAGS_TRIALS, trials->count); \
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
	        results_t *results = alloc_results(testname, eSMART_GENERIC_FLAG_TRIALS, trials->count); \
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
	        results_t *results = alloc_results(testname, eSMART_VM_PROT_TRIALS, trials->count); \
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
	        results_t *results = alloc_results(testname, eSMART_VM_PROT_PAIR_TRIALS, trials->count); \
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
	        results_t *results = alloc_results(testname, eSMART_VM_PROT_PAIR_TRIALS, trials->count); \
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
	        results_t *results = alloc_results(testname, eSMART_VM_PROT_TRIALS, trials->count); \
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
	        results_t *results = alloc_results(testname, eSMART_LEDGER_FLAG_TRIALS, trials->count); \
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
	        results_t *results = alloc_results(testname, eSMART_LEDGER_TAG_TRIALS, trials->count); \
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
	        results_t *results = alloc_results(testname, eSMART_VM_INHERIT_TRIALS, trials->count); \
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
	test_ ## NAME ## mach_with_allocated_start_end(NAME ## with_start_end_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        start_size_trials_t *trials SMART_START_SIZE_TRIALS(base.addr); \
	        results_t *results = alloc_results(testname, eSMART_START_SIZE_TRIALS, base.addr, trials->count); \
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
	test_ ## NAME ## mach_with_allocated_tag(NAME ## with_tag_fn fn, const char *testname) \
	{                                                               \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        vm_tag_trials_t *trials SMART_VM_TAG_TRIALS();  \
	        results_t *results = alloc_results(testname, eSMART_VM_TAG_TRIALS, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                kern_return_t ret = fn(map, (T)base.addr, (T)(base.addr + base.size), trials->list[i].tag); \
	                append_result(results, ret, trials->list[i].name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
	/* Test a Mach function. */                                     \
	/* Run each trial with an allocated region and a vm_behavior_t. */ \
	typedef kern_return_t (*NAME ## mach_behavior_fn)(MAP_T map, T addr, T size, vm_behavior_t behavior); \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_allocated_aligned_vm_behavior_t(NAME ## mach_behavior_fn fn, mach_vm_size_t align_mask, const char * testname) { \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_ALIGNED_VM(map, TEST_ALLOC_SIZE, align_mask, VM_PROT_DEFAULT); \
	        vm_behavior_trials_t *trials SMART_VM_BEHAVIOR_TRIALS();  \
	        results_t *results = alloc_results(testname, eSMART_VM_BEHAVIOR_TRIALS, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                vm_behavior_trial_t trial = trials->list[i];     \
	                int ret = fn(map, (T)base.addr, (T)base.size, trial.value); \
	                append_result(results, ret, trial.name); \
	        }                                                       \
	        return results;                                         \
	}                                                               \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_allocated_vm_behavior_t(NAME ## mach_behavior_fn fn, const char * testname) { \
	        return test_ ## NAME ## mach_with_allocated_aligned_vm_behavior_t(fn, 0, testname); \
	}                                                               \
                                                                        \
	/* Test a Mach function. */                                     \
	/* Run each trial with an allocated region and a vm_sync_t. */ \
	typedef kern_return_t (*NAME ## mach_sync_fn)(MAP_T map, T addr, T size, vm_sync_t behavior); \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_allocated_vm_sync_t(NAME ## mach_sync_fn fn, const char * testname) { \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        vm_sync_trials_t *trials SMART_VM_SYNC_TRIALS(); \
	        results_t *results = alloc_results(testname, eSMART_VM_SYNC_TRIALS, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                vm_sync_trial_t trial = trials->list[i];    \
	                int ret = fn(map, (T)base.addr, (T)base.size, trial.value); \
	                append_result(results, ret, trial.name);        \
	        }                                                       \
	        return results;                                         \
	}                                                               \
	/* Test a Mach function. */                                     \
	/* Run each trial with an allocated region and a vm_machine_attribute_t. */ \
	typedef kern_return_t (*NAME ## mach_attribute_fn)(MAP_T map, T addr, T size, vm_machine_attribute_t attr); \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_allocated_vm_machine_attribute_t(NAME ## mach_attribute_fn fn, const char * testname) { \
	        MAP_T map SMART_MAP;                                    \
	        allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	        vm_machine_attribute_trials_t *trials SMART_VM_MACHINE_ATTRIBUTE_TRIALS(); \
	        results_t *results = alloc_results(testname, eSMART_VM_MACHINE_ATTRIBUTE_TRIALS, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                vm_machine_attribute_trial_t trial = trials->list[i];    \
	                int ret = fn(map, (T)base.addr, (T)base.size, trial.value); \
	                append_result(results, ret, trial.name);        \
	        }                                                       \
	        return results;                                         \
	}                                                               \
	/* Test a Mach function. */                                     \
	/* Run each trial with an allocated region and a purgeable trial. */ \
	typedef kern_return_t (*NAME ## mach_purgable_fn)(MAP_T map, T addr, vm_purgable_t control, int state); \
                                                                        \
	static results_t * __attribute__((used))                        \
	test_ ## NAME ## mach_with_allocated_purgeable_and_state(NAME ## mach_purgable_fn fn, const char * testname) { \
	        MAP_T map SMART_MAP;                                    \
	        vm_purgeable_and_state_trials_t *trials SMART_VM_PURGEABLE_AND_STATE_TRIALS(); \
	        results_t *results = alloc_results(testname, eSMART_VM_PURGEABLE_AND_STATE_TRIALS, trials->count); \
                                                                        \
	        for (unsigned i = 0; i < trials->count; i++) {          \
	                allocation_t base SMART_ALLOCATE_PURGEABLE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT); \
	                vm_purgeable_and_state_trial_t trial = trials->list[i];    \
	                int ret = fn(map, (T)base.addr, trial.control, trial.state); \
	                append_result(results, ret, trial.name);        \
	        }                                                       \
	        return results;                                         \
	}

IMPL(, uint64_t)
#if TEST_OLD_STYLE_MACH
IMPL(old, uint32_t)
#endif
#undef IMPL

#if KERNEL && CONFIG_MAP_RANGES
/*
 * The vm_range_create tests assume we don't ever do range_creates that should succeed
 * that take more than 2 * PAGE_SIZE. This enforces that.
 */
void
verify_largest_valid_trial_size_fits(start_size_start_size_trial_t trial)
{
	if (trial.size > 2 * PAGE_SIZE) {
		assert(trial.size > 0xfffffffffffffff);
	}
	if (trial.second_size > 2 * PAGE_SIZE) {
		assert(trial.second_size > 0xfffffffffffffff);
	}
}

/* Run each trial with start/size/start/size parameters. */
typedef kern_return_t (mach_with_start_size_start_size_fn)(MAP_T map, mach_vm_address_t addr,
    mach_vm_size_t size, mach_vm_address_t second_addr, mach_vm_size_t second_size);

static results_t * __attribute__((used))
test_mach_vm_range_create(mach_with_start_size_start_size_fn fn, const char *testname)
{
	start_size_start_size_trials_t *trials SMART_START_SIZE_START_SIZE_TRIALS();
	results_t *results = alloc_results(testname, eSMART_START_SIZE_START_SIZE_TRIALS, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		/*
		 * Allocate and configure a new map for every trial so that the map has no user ranges.
		 */
		MAP_T map SMART_RANGE_MAP;
		bool has_ranges = vm_map_range_configure(map, false) == KERN_SUCCESS;
		bool has_space_in_ranges = false;

		struct mach_vm_range void1 = {
			.min_address = map->default_range.max_address,
			.max_address = map->data_range.min_address,
		};
		struct mach_vm_range void2 = {
			.min_address = map->data_range.max_address,
			.max_address = vm_map_max(map),
		};
		struct mach_vm_range range_to_test;

		/*
		 * For our tests to succeed for good cases, but also trigger failures
		 * when overlap occurs we need:
		 * range1 = {.start = addr}, range2 = {.start = addr + PAGE_SIZE * 2}.
		 * We also want at least 2 * PAGE_SIZE memory available after the start of range2.
		 * We additionally start our first range 2 PAGE_SIZE away from the start.
		 */
		if (void1.min_address + (PAGE_SIZE * 6) < void1.max_address) {
			range_to_test = void1;
			has_space_in_ranges = true;
		} else if (void2.min_address + (PAGE_SIZE * 6) < void2.max_address) {
			range_to_test = void2;
			has_space_in_ranges = true;
		}

		mach_vm_address_t addr_base = range_to_test.min_address + PAGE_SIZE * 2;
		if (has_ranges && has_space_in_ranges) {
			mach_vm_address_t second_addr_base = addr_base + PAGE_SIZE * 2;

			start_size_start_size_trial_t trial = slide_trial(trials->list[i], addr_base, second_addr_base);

			verify_largest_valid_trial_size_fits(trial);

			mach_vm_address_t start = trial.start;
			mach_vm_size_t size = trial.size;
			mach_vm_address_t second_start = trial.second_start;
			mach_vm_size_t second_size = trial.second_size;
			kern_return_t ret = fn(map, start, size, second_start, second_size);
			append_result(results, ret, trials->list[i].name);
		} else {
			append_result(results, IGNORED, trials->list[i].name);
		}
	}
	return results;
}
#endif /* KERNEL && CONFIG_MAP_RANGES */

// Test a mach allocation function with a start/size
static results_t *
test_mach_allocation_func_with_start_size(kern_return_t (*func)(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size), const char * testname)
{
	MAP_T map SMART_MAP;
	start_size_trials_t *trials SMART_START_SIZE_TRIALS(0);
	results_t *results = alloc_results(testname, eSMART_START_SIZE_TRIALS, 0, trials->count);

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
	results_t *results = alloc_results(testname, eSMART_VM_MAP_KERNEL_FLAGS_TRIALS, trials->count);

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
	results_t *results = alloc_results(testname, eSMART_VM_MAP_KERNEL_FLAGS_TRIALS, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		kern_return_t ret = func(map, base.addr, base.size, trials->list[i].flags);
		append_result(results, ret, trials->list[i].name);
	}
	return results;
}

static results_t *
test_unix_with_allocated_vm_prot_t(int (*func)(void * start, size_t size, int flags), const char * testname)
{
	MAP_T map CURRENT_MAP;
	allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	vm_prot_trials_t * trials SMART_VM_PROT_TRIALS();
	results_t *results = alloc_results(testname, eSMART_VM_PROT_TRIALS, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		int ret = func((void *) base.addr, (size_t) base.size, (int) trials->list[i].prot);
		append_result(results, ret, trials->list[i].name);
	}
	return results;
}

// Test a Unix function.
// Run each trial with an allocated vm region and start/size parameters that reference it.
typedef int (*unix_with_start_size_fn)(void *start, size_t size);

static results_t * __unused
test_unix_with_allocated_aligned_start_size(unix_with_start_size_fn fn, mach_vm_size_t align_mask, const char *testname)
{
	MAP_T map CURRENT_MAP;
	allocation_t base SMART_ALLOCATE_ALIGNED_VM(map, TEST_ALLOC_SIZE, align_mask, VM_PROT_DEFAULT);
	start_size_trials_t *trials SMART_START_SIZE_TRIALS(base.addr);
	results_t *results = alloc_results(testname, eSMART_START_SIZE_TRIALS, base.addr, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		addr_t start = trials->list[i].start;
		addr_t size = trials->list[i].size;
		int ret = fn((void*)(uintptr_t)start, (size_t)size);
		append_result(results, ret, trials->list[i].name);
	}
	return results;
}

static results_t * __unused
test_unix_with_allocated_start_size(unix_with_start_size_fn fn, const char *testname)
{
	return test_unix_with_allocated_aligned_start_size(fn, 0, testname);
}

#if KERNEL
static results_t * __unused
test_kext_unix_with_allocated_start_size(unix_with_start_size_fn fn, const char *testname)
{
	MAP_T map CURRENT_MAP;
	allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	start_size_trials_t *trials SMART_START_SIZE_TRIALS(base.addr);
	results_t *results = alloc_results(testname, eSMART_START_SIZE_TRIALS, base.addr, trials->count);

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
	MAP_T map CURRENT_MAP;
	allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	addr_trials_t *trials SMART_ADDR_TRIALS(base.addr);
	results_t *results = alloc_results(testname, eSMART_ADDR_TRIALS, base.addr, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		mach_vm_address_t addr = (mach_vm_address_t)trials->list[i].addr;
		kern_return_t ret = func(map, addr);
		append_result(results, ret, trials->list[i].name);
	}
	return results;
}
#endif /* KERNEL */

static results_t * __attribute__((used))
test_with_int64(kern_return_t (*func)(int64_t), const char *testname)
{
	size_trials_t *trials SMART_SIZE_TRIALS();
	results_t *results = alloc_results(testname, eSMART_SIZE_TRIALS, trials->count);

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

	results_t *results = alloc_results(testname, eSMART_START_SIZE_TRIALS, 0, trials->count);

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
	results_t *results = alloc_results(testname, eSMART_SRC_DST_SIZE_TRIALS, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		/*
		 * Require src < dst. Some tests may get different error codes if src > dst.
		 *
		 * Example: size == -dst-1 for functions like vm_remap where dst
		 * is a hint (i.e. dst + size overflow is ok) (rdar://132099195).
		 * If src > dst then src + size overflows and the
		 *   function returns KERN_INVALID_ARGUMENT.
		 * If src < dst then src + size does not overflow and the
		 *   function fails and returns KERN_INVALID_ADDRESS because
		 *   [src, src + size) is an unreasonable address range.
		 *
		 * TODO: test both src < dst and src > dst.
		 */
		src_dst_size_trial_t trial = trials->list[i];
		unallocation_t dst_base SMART_UNALLOCATE_VM_AFTER(map, src_base.addr, TEST_ALLOC_SIZE);
		assert(src_base.addr < dst_base.addr);

		trial = slide_trial_src(trial, src_base.addr);
		trial = slide_trial_dst(trial, dst_base.addr);
		int ret = func(map, trial.src, trial.size, trial.dst);
		// func deallocates its own allocation
		append_result(results, ret, trial.name);
	}
	return results;
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

static kern_return_t
call_mach_vm_behavior_set__start_size__default(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	kern_return_t kr = mach_vm_behavior_set(map, start, size, VM_BEHAVIOR_DEFAULT);
	return kr;
}

/*
 * VM_BEHAVIOR_CAN_REUSE is additionally tested as it uses slightly different page rounding semantics
 */
static kern_return_t
call_mach_vm_behavior_set__start_size__can_reuse(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	kern_return_t kr = mach_vm_behavior_set(map, start, size, VM_BEHAVIOR_CAN_REUSE);
	return kr;
}

static kern_return_t
call_mach_vm_behavior_set__vm_behavior(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_behavior_t behavior)
{
	kern_return_t kr = mach_vm_behavior_set(map, start, size, behavior);
	return kr;
}

static void
check_mach_vm_purgable_control_outparam_changes(kern_return_t * kr, int state, int saved_state, int control)
{
	if (*kr == KERN_SUCCESS) {
		if (control == VM_PURGABLE_PURGE_ALL || VM_PURGABLE_SET_STATE) {
			if (state != saved_state) {
				*kr = OUT_PARAM_BAD;
			}
		}
		if (control == VM_PURGABLE_GET_STATE) {
			/*
			 * The default state is VM_PURGABLE_NONVOLATILE for a newly created region
			 */
			if (state != VM_PURGABLE_NONVOLATILE) {
				*kr = OUT_PARAM_BAD;
			}
		}
	} else {
		if (state != saved_state) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

static void
check_mach_vm_region_outparam_changes(kern_return_t * kr, MAP_T map, void * info, void * saved_info, size_t info_size,
    mach_port_t object_name, mach_port_t saved_object_name, mach_vm_address_t addr, mach_vm_address_t saved_addr,
    mach_vm_size_t size, mach_vm_size_t saved_size)
{
	if (*kr == KERN_SUCCESS) {
		if (object_name != 0) {
			*kr = OUT_PARAM_BAD;
		}
		if (addr < trunc_down_map(map, saved_addr)) {
			*kr = OUT_PARAM_BAD;
		}
		if (size == saved_size) {
			*kr = OUT_PARAM_BAD;
		}
		if (memcmp(info, saved_info, info_size) == 0) {
			*kr = OUT_PARAM_BAD;
		}
	} else {
		if (object_name != saved_object_name || addr != saved_addr || size != saved_size || memcmp(info, saved_info, info_size) != 0) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

static int
call_mach_vm_region(MAP_T map, mach_vm_address_t addr)
{
	mach_vm_address_t addr_cpy = addr;
	mach_vm_size_t size_out = UNLIKELY_INITIAL_SIZE;
	mach_vm_size_t saved_size = size_out;
	mach_port_t object_name_out = UNLIKELY_INITIAL_MACH_PORT;
	mach_port_t saved_name = object_name_out;
	vm_region_basic_info_data_64_t info;
	info.inheritance = INVALID_INHERIT;
	vm_region_basic_info_data_64_t saved_info = info;

	mach_msg_type_number_t infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
	kern_return_t kr = mach_vm_region(map, &addr_cpy, &size_out, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info,
	    &infoCnt, &object_name_out);
	check_mach_vm_region_outparam_changes(&kr, map, &info, &saved_info, sizeof(info), object_name_out, saved_name, addr_cpy, addr, size_out, saved_size);

	return kr;
}

#if TEST_OLD_STYLE_MACH || KERNEL
static int
call_vm_region(MAP_T map, vm_address_t addr)
{
	vm_address_t addr_cpy = addr;
	vm_size_t size_out = UNLIKELY_INITIAL_SIZE;
	vm_size_t saved_size = size_out;
	mach_port_t object_name_out = UNLIKELY_INITIAL_MACH_PORT;
	mach_port_t saved_name = object_name_out;
	vm_region_basic_info_data_64_t info;
	info.inheritance = INVALID_INHERIT;
	vm_region_basic_info_data_64_t saved_info = info;

	mach_msg_type_number_t infoCnt = VM_REGION_BASIC_INFO_COUNT_64;
	kern_return_t kr = vm_region(map, &addr_cpy, &size_out, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info,
	    &infoCnt, &object_name_out);
	check_mach_vm_region_outparam_changes(&kr, map, &info, &saved_info, sizeof(info), object_name_out, saved_name, addr_cpy, addr, size_out, saved_size);

	return kr;
}
#endif /* TEST_OLD_STYLE_MACH || KERNEL */

static void
check_mach_vm_page_info_outparam_changes(kern_return_t * kr, vm_page_info_basic_data_t info, vm_page_info_basic_data_t saved_info,
    mach_msg_type_number_t count, mach_msg_type_number_t saved_count)
{
	if (*kr == KERN_SUCCESS) {
		if (memcmp(&info, &saved_info, sizeof(vm_page_info_basic_data_t)) == 0) {
			*kr = OUT_PARAM_BAD;
		}
	} else {
		if (memcmp(&info, &saved_info, sizeof(vm_page_info_basic_data_t)) != 0) {
			*kr = OUT_PARAM_BAD;
		}
	}
	if (count != saved_count) {
		*kr = OUT_PARAM_BAD;
	}
}

#pragma clang diagnostic pop

// VM_PARAMETER_VALIDATION_H
#endif
