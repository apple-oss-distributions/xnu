#include <kern/zalloc.h>
#include <kern/thread_test_context.h>

#include "vm_parameter_validation.h"

#pragma clang diagnostic ignored "-Wdeclaration-after-statement"
#pragma clang diagnostic ignored "-Wincompatible-function-pointer-types"
#pragma clang diagnostic ignored "-Wmissing-prototypes"
#pragma clang diagnostic ignored "-Wpedantic"
#pragma clang diagnostic ignored "-Wgcc-compat"


// Kernel sysctl test prints its output into a userspace buffer.
// fixme these global variables prevent test concurrency

static user_addr_t SYSCTL_OUTPUT_BUF;
static user_addr_t SYSCTL_OUTPUT_END;

// This is a read/write fd passed from userspace.
// It's passed to make it easier for kernel tests to interact with a file.
static int file_descriptor;

// Output to create a golden test result in kern test, controlled by
// MSB in file_descriptor and set by GENERATE_GOLDEN_IMAGE from userspace.
bool kernel_generate_golden = FALSE;

// vprintf() to a userspace buffer
// output is incremented to point at the new nul terminator
static void
user_vprintf(user_addr_t *output, user_addr_t output_end, const char *format, va_list args) __printflike(3, 0)
{
	extern int vsnprintf(char *, size_t, const char *, va_list) __printflike(3, 0);
	char linebuf[1024];
	size_t printed;

	printed = vsnprintf(linebuf, sizeof(linebuf), format, args);
	assert(printed < sizeof(linebuf) - 1);
	assert(*output + printed + 1 < output_end);
	copyout(linebuf, *output, printed + 1);
	*output += printed;
}

void
testprintf(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	user_vprintf(&SYSCTL_OUTPUT_BUF, SYSCTL_OUTPUT_END, format, args);
	va_end(args);
}

// Utils

static mach_port_t
make_a_mem_object(vm_size_t size)
{
	ipc_port_t out_handle;
	kern_return_t kr = mach_memory_object_memory_entry_64((host_t)1, /*internal=*/ true, size, VM_PROT_READ | VM_PROT_WRITE, 0, &out_handle);
	assert(kr == 0);
	return out_handle;
}

static mach_port_t
make_a_mem_entry(MAP_T map, vm_size_t size)
{
	mach_port_t port;
	memory_object_size_t s = (memory_object_size_t)size;
	kern_return_t kr = mach_make_memory_entry_64(map, &s, (memory_object_offset_t)0, MAP_MEM_NAMED_CREATE | MAP_MEM_LEDGER_TAGGED, &port, MACH_PORT_NULL);
	assert(kr == 0);
	return port;
}

// Test functions

static results_t *
test_vm_map_copy_overwrite(kern_return_t (*func)(MAP_T dst_map, vm_map_copy_t copy, mach_vm_address_t start, mach_vm_size_t size), const char * testname)
{
	// source map: has an allocation bigger than our
	// "reasonable" trial sizes, to copy from
	MAP_T src_map SMART_MAP;
	allocation_t src_alloc SMART_ALLOCATE_VM(src_map, TEST_ALLOC_SIZE, VM_PROT_READ);

	// dest map: has an allocation bigger than our
	// "reasonable" trial sizes, to copy-overwrite on
	MAP_T dst_map SMART_MAP;
	allocation_t dst_alloc SMART_ALLOCATE_VM(dst_map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);

	// We test dst/size parameters.
	// We don't test the contents of the vm_map_copy_t.
	start_size_trials_t *trials SMART_START_SIZE_TRIALS(dst_alloc.addr);
	results_t *results = alloc_results(testname, eSMART_START_SIZE_TRIALS, dst_alloc.addr, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		start_size_trial_t trial = trials->list[i];

		// Copy from the source.
		vm_map_copy_t copy;
		kern_return_t kr = vm_map_copyin(src_map, src_alloc.addr, src_alloc.size, false, &copy);
		assert(kr == 0);
		assert(copy);  // null copy won't exercise the sanitization path

		// Copy-overwrite to the destination.
		kern_return_t ret = func(dst_map, copy, trial.start, trial.size);

		if (ret != KERN_SUCCESS) {
			vm_map_copy_discard(copy);
		}
		append_result(results, ret, trial.name);
	}
	return results;
}

/*
 * This function temporarily allocates a writeable allocation in kernel_map, and a read only allocation in a temporary map.
 * It's used to test a function such as vm_map_read_user which copies in data to a kernel pointer that must be writeable.
 */
static results_t *
test_src_kerneldst_size(kern_return_t (*func)(MAP_T map, vm_map_offset_t src, void * dst, vm_size_t length), const char * testname)
{
	MAP_T map SMART_MAP;
	allocation_t src_base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_READ);
	allocation_t dst_base SMART_ALLOCATE_VM(kernel_map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	src_dst_size_trials_t * trials SMART_SRC_DST_SIZE_TRIALS();
	results_t *results = alloc_results(testname, eSMART_SRC_DST_SIZE_TRIALS, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		src_dst_size_trial_t trial = trials->list[i];
		trial = slide_trial_src(trial, src_base.addr);
		trial = slide_trial_dst(trial, dst_base.addr);
		int ret = func(map, trial.src, (void *)trial.dst, trial.size);
		append_result(results, ret, trial.name);
	}
	return results;
}

/*
 * This function temporarily allocates a read only allocation in kernel_map, and a writeable allocation in a temporary map.
 * It's used to test a function such as vm_map_write_user which copies data from a kernel pointer to a writeable userspace address.
 */
static results_t *
test_kernelsrc_dst_size(kern_return_t (*func)(MAP_T map, void *src, vm_map_offset_t dst, vm_size_t length), const char * testname)
{
	MAP_T map SMART_MAP;
	allocation_t src_base SMART_ALLOCATE_VM(kernel_map, TEST_ALLOC_SIZE, VM_PROT_READ);
	allocation_t dst_base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	src_dst_size_trials_t * trials SMART_SRC_DST_SIZE_TRIALS();
	results_t *results = alloc_results(testname, eSMART_SRC_DST_SIZE_TRIALS, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		src_dst_size_trial_t trial = trials->list[i];
		trial = slide_trial_src(trial, src_base.addr);
		trial = slide_trial_dst(trial, dst_base.addr);
		int ret = func(map, (void *)trial.src, trial.dst, trial.size);
		append_result(results, ret, trial.name);
	}
	return results;
}


/////////////////////////////////////////////////////
// Mach tests


static kern_return_t
call_mach_vm_read(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	vm_offset_t out_addr;
	mach_msg_type_number_t out_size;
	kern_return_t kr = mach_vm_read(map, start, size, &out_addr, &out_size);
	if (kr == 0) {
		// we didn't call through MIG so out_addr is really a vm_map_copy_t
		vm_map_copy_discard((vm_map_copy_t)out_addr);
	}
	return kr;
}

static inline void
check_vm_map_copyin_outparam_changes(kern_return_t * kr, vm_map_copy_t copy, vm_map_copy_t saved_copy)
{
	if (*kr == KERN_SUCCESS) {
		if (copy == saved_copy) {
			*kr = OUT_PARAM_BAD;
		}
	} else {
		if (copy != saved_copy) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

static kern_return_t
call_vm_map_copyin(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	vm_map_copy_t invalid_initial_value = INVALID_VM_MAP_COPY;
	vm_map_copy_t copy = invalid_initial_value;
	kern_return_t kr = vm_map_copyin(map, start, size, false, &copy);
	if (kr == 0) {
		vm_map_copy_discard(copy);
	}
	check_vm_map_copyin_outparam_changes(&kr, copy, invalid_initial_value);
	return kr;
}

static kern_return_t
call_copyoutmap_atomic32(MAP_T map, vm_map_offset_t addr)
{
	uint32_t data = 0;
	kern_return_t kr = copyoutmap_atomic32(map, data, addr);
	return kr;
}


static kern_return_t
call_mach_vm_allocate__flags(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size, int flags)
{
	mach_vm_address_t saved_start = *start;
	kern_return_t kr = mach_vm_allocate_external(map, start, size, flags);
	check_mach_vm_allocate_outparam_changes(&kr, *start, size, saved_start, flags, map);
	return kr;
}

static kern_return_t
call_mach_vm_allocate__start_size_fixed(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size)
{
	mach_vm_address_t saved_start = *start;
	kern_return_t kr = mach_vm_allocate_external(map, start, size, VM_FLAGS_FIXED);
	check_mach_vm_allocate_outparam_changes(&kr, *start, size, saved_start, VM_FLAGS_FIXED, map);
	return kr;
}

static kern_return_t
call_mach_vm_allocate__start_size_anywhere(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size)
{
	mach_vm_address_t saved_start = *start;
	kern_return_t kr = mach_vm_allocate_external(map, start, size, VM_FLAGS_ANYWHERE);
	check_mach_vm_allocate_outparam_changes(&kr, *start, size, saved_start, VM_FLAGS_ANYWHERE, map);
	return kr;
}

static kern_return_t
call_mach_vm_allocate_kernel__flags(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size, int flags)
{
	mach_vm_address_t saved_start = *start;
	kern_return_t kr = mach_vm_allocate_kernel(map, start, size,
	    FLAGS_AND_TAG(flags, VM_KERN_MEMORY_OSFMK));
	check_mach_vm_allocate_outparam_changes(&kr, *start, size, saved_start, flags, map);
	return kr;
}

static kern_return_t
call_mach_vm_allocate_kernel__start_size_fixed(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size)
{
	if (dealloc_would_time_out(*start, size, map)) {
		return ACCEPTABLE;
	}

	mach_vm_address_t saved_start = *start;
	kern_return_t kr = mach_vm_allocate_kernel(map, start, size,
	    FLAGS_AND_TAG(VM_FLAGS_FIXED, VM_KERN_MEMORY_OSFMK));
	check_mach_vm_allocate_outparam_changes(&kr, *start, size, saved_start, VM_FLAGS_FIXED, map);
	return kr;
}

static kern_return_t
call_mach_vm_allocate_kernel__start_size_anywhere(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size)
{
	if (dealloc_would_time_out(*start, size, map)) {
		return ACCEPTABLE;
	}

	mach_vm_address_t saved_start = *start;
	kern_return_t kr = mach_vm_allocate_kernel(map, start, size,
	    FLAGS_AND_TAG(VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_OSFMK));
	check_mach_vm_allocate_outparam_changes(&kr, *start, size, saved_start, VM_FLAGS_ANYWHERE, map);
	return kr;
}



static kern_return_t
call_vm_allocate__flags(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size, int flags)
{
	mach_vm_address_t saved_start = *start;
	kern_return_t kr = vm_allocate(map, (vm_address_t *) start, (vm_size_t) size, flags);
	check_mach_vm_allocate_outparam_changes(&kr, *start, size, saved_start, flags, map);
	return kr;
}

static kern_return_t
call_vm_allocate__start_size_fixed(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size)
{
	mach_vm_address_t saved_start = *start;
	kern_return_t kr = vm_allocate(map, (vm_address_t *) start, (vm_size_t) size, VM_FLAGS_FIXED);
	check_mach_vm_allocate_outparam_changes(&kr, *start, size, saved_start, VM_FLAGS_FIXED, map);
	return kr;
}

static kern_return_t
call_vm_allocate__start_size_anywhere(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size)
{
	mach_vm_address_t saved_start = *start;
	kern_return_t kr = vm_allocate(map, (vm_address_t *) start, (vm_size_t) size, VM_FLAGS_ANYWHERE);
	check_mach_vm_allocate_outparam_changes(&kr, *start, size, saved_start, VM_FLAGS_ANYWHERE, map);
	return kr;
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

// Including sys/systm.h caused things to blow up
int     vslock(user_addr_t addr, user_size_t len);
int     vsunlock(user_addr_t addr, user_size_t len, int dirtied);
static int
call_vslock(void * start, size_t size)
{
	int kr = vslock((user_addr_t) start, (user_size_t) size);
	if (kr == KERN_SUCCESS) {
		(void) vsunlock((user_addr_t) start, (user_size_t) size, 0);
	}

	return kr;
}

static int
call_vsunlock_undirtied(void * start, size_t size)
{
	int kr = vslock((user_addr_t) start, (user_size_t) size);
	if (kr == EINVAL) {
		// Invalid vslock arguments should also be
		// invalid vsunlock arguments. Test it.
	} else if (kr != KERN_SUCCESS) {
		// vslock failed, and vsunlock of non-locked memory panics
		return PANIC;
	}
	kr = vsunlock((user_addr_t) start, (user_size_t) size, 0);
	return kr;
}

static int
call_vsunlock_dirtied(void * start, size_t size)
{
	int kr = vslock((user_addr_t) start, (user_size_t) size);
	if (kr == EINVAL) {
		// Invalid vslock arguments should also be
		// invalid vsunlock arguments. Test it.
	} else if (kr != KERN_SUCCESS) {
		// vslock failed, and vsunlock of non-locked memory panics
		return PANIC;
	}
	kr = vsunlock((user_addr_t) start, (user_size_t) size, 1);
	return kr;
}

extern kern_return_t    vm_map_wire_external(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vm_prot_t               access_type,
	boolean_t               user_wire);


typedef kern_return_t (*wire_fn_t)(
	vm_map_t task,
	mach_vm_address_t start,
	mach_vm_address_t end,
	vm_prot_t prot,
	vm_tag_t tag,
	boolean_t user_wire);


/*
 * Tell vm_tag_bt() to change its behavior so our calls to
 * vm_map_wire_external and vm_map_wire_and_extract do not panic.
 */
static void
prevent_wire_tag_panic(bool prevent)
{
	thread_set_test_option(test_option_vm_prevent_wire_tag_panic, prevent);
}

#if XNU_PLATFORM_MacOSX
// vm_map_wire_and_extract() implemented on macOS only


/*
 * wire_nested requires a range of exactly one page when passed a physpage pointer.
 * wire_and_extract is meant to provide that, but as a result of round introduced, unaligned values don't follow that.
 */
static bool
will_vm_map_wire_nested_panic_due_to_invalid_range_size(MAP_T map, mach_vm_address_t start)
{
	mach_vm_address_t end = start + VM_MAP_PAGE_SIZE(map);
	if (round_up_map(map, end) - trunc_down_map(map, start) != VM_MAP_PAGE_SIZE(map)) {
		return true;
	}
	return false;
}

static inline void
check_vm_map_wire_and_extract_outparam_changes(kern_return_t * kr, ppnum_t physpage)
{
	if (*kr != KERN_SUCCESS) {
		if (physpage != 0) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

static kern_return_t
vm_map_wire_and_extract_retyped(
	vm_map_t                map,
	mach_vm_address_t       start,
	mach_vm_address_t       end __unused,
	vm_prot_t               prot,
	vm_tag_t                tag __unused,
	boolean_t               user_wire)
{
	if (will_vm_map_wire_nested_panic_due_to_invalid_range_size(map, start)) {
		return PANIC;
	}

	ppnum_t physpage = UNLIKELY_INITIAL_PPNUM;
	kern_return_t kr = vm_map_wire_and_extract(map, start, prot, user_wire, &physpage);
	check_vm_map_wire_and_extract_outparam_changes(&kr, physpage);
	return kr;
}
#endif // XNU_PLATFORM_MacOSX


static kern_return_t
vm_map_wire_external_retyped(
	vm_map_t                map,
	mach_vm_address_t       start,
	mach_vm_address_t       end,
	vm_prot_t               prot,
	vm_tag_t                tag __unused,
	boolean_t               user_wire)
{
	return vm_map_wire_external(map, start, end, prot, user_wire);
}

static kern_return_t
wire_call_impl(wire_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t end, vm_prot_t prot, vm_tag_t tag, bool user_wire)
{
	if (tag == VM_KERN_MEMORY_NONE) {
		return PANIC;
	}
	prevent_wire_tag_panic(true);
	kern_return_t kr = fn(map, start, end, prot, tag, user_wire);
	prevent_wire_tag_panic(false);
	if (kr == KERN_SUCCESS) {
		(void) vm_map_unwire(map, start, end, user_wire);
	}
	return kr;
}

#define WIRE_IMPL(FN, user_wire)                                                  \
	static kern_return_t                                                      \
	__attribute__((used))                                                     \
	call_ ## FN ## __start_end__user_wired_ ## user_wire ## _(MAP_T map, mach_vm_address_t start, mach_vm_address_t end) \
	{                                                                         \
	        return wire_call_impl(FN, map, start, end, VM_PROT_DEFAULT, VM_KERN_MEMORY_OSFMK, user_wire); \
	}                                                                         \
	static kern_return_t                                                      \
	__attribute__((used))                                                     \
	call_ ## FN ## __prot__user_wired_ ## user_wire ## _(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_prot_t prot) \
	{                                                                         \
	        mach_vm_address_t end;                                            \
	        if (__builtin_add_overflow(start, size, &end)) {                  \
	                return BUSTED;                                            \
	        }                                                                 \
	        return wire_call_impl(FN, map, start, end, prot, VM_KERN_MEMORY_OSFMK, user_wire); \
	}                                                                         \
	static kern_return_t                                                      \
	__attribute__((used))                                                     \
	call_ ## FN ## __tag__user_wired_ ## user_wire ## _(MAP_T map, mach_vm_address_t start, mach_vm_address_t end, vm_tag_t tag) \
	{                                                                         \
	        kern_return_t kr = wire_call_impl(FN, map, start, end, VM_PROT_DEFAULT, tag, user_wire); \
	        return kr;                                                        \
	}                                                                         \
	static kern_return_t                                                      \
	__attribute__((used))                                                     \
	call_ ## FN ## __start__user_wired_ ## user_wire ## _(MAP_T map, mach_vm_address_t start) \
	{                                                                         \
	        return wire_call_impl(FN, map, start, 0, VM_PROT_DEFAULT, VM_KERN_MEMORY_OSFMK, user_wire); \
	}                                                                         \

WIRE_IMPL(vm_map_wire_external_retyped, true)
WIRE_IMPL(vm_map_wire_external_retyped, false)
WIRE_IMPL(vm_map_wire_kernel, true)
WIRE_IMPL(vm_map_wire_kernel, false)

#if XNU_PLATFORM_MacOSX
WIRE_IMPL(vm_map_wire_and_extract_retyped, true)
WIRE_IMPL(vm_map_wire_and_extract_retyped, false)
#endif

static kern_return_t
call_mach_vm_wire_level_monitor(int64_t requested_pages)
{
	kern_return_t kr = mach_vm_wire_level_monitor(requested_pages);
	return kr;
}

static kern_return_t
call_vm_map_unwire_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_address_t end)
{
	kern_return_t kr = vm_map_unwire(map, start, end, TRUE);
	return kr;
}


static kern_return_t
call_vm_map_unwire_non_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_address_t end)
{
	kern_return_t kr = vm_map_wire_kernel(map, start, end, VM_PROT_DEFAULT, VM_KERN_MEMORY_OSFMK, FALSE);
	if (kr) {
		return PANIC;
	}
	kr = vm_map_unwire(map, start, end, FALSE);
	return kr;
}

#ifndef __x86_64__
extern const vm_map_address_t physmap_base;
extern const vm_map_address_t physmap_end;
#endif

/*
 * This function duplicates the panicking checks done in copy_validate.
 * size==0 is returned as success earlier in copyin/out than copy_validate is called, so we ignore that case.
 */
static bool
will_copyio_panic_in_copy_validate(void *kernel_addr, vm_size_t size)
{
	if (size == 0) {
		return false;
	}
	extern const int copysize_limit_panic;
	if (size > copysize_limit_panic) {
		return true;
	}

	/*
	 * copyio is architecture specific and has different checks per arch.
	 */
#ifdef __x86_64__
	if ((vm_offset_t) kernel_addr < VM_MIN_KERNEL_AND_KEXT_ADDRESS) {
		return true;
	}
#else /* not __x86_64__ */
	uintptr_t kernel_addr_last;
	if (os_add_overflow((uintptr_t) kernel_addr, size, &kernel_addr_last)) {
		return true;
	}

	bool in_kva = (VM_KERNEL_STRIP_UPTR(kernel_addr) >= VM_MIN_KERNEL_ADDRESS) &&
	    (VM_KERNEL_STRIP_UPTR(kernel_addr_last) <= VM_MAX_KERNEL_ADDRESS);
	bool in_physmap = (VM_KERNEL_STRIP_UPTR(kernel_addr) >= physmap_base) &&
	    (VM_KERNEL_STRIP_UPTR(kernel_addr_last) <= physmap_end);

	if (!(in_kva || in_physmap)) {
		return true;
	}
#endif /* not __x86_64__ */

	return false;
}

static kern_return_t
call_copyinmap(MAP_T map, vm_map_offset_t fromaddr, void * todata, vm_size_t length)
{
	if (will_copyio_panic_in_copy_validate(todata, length)) {
		return PANIC;
	}

	kern_return_t kr = copyinmap(map, fromaddr, todata, length);
	return kr;
}

static kern_return_t
call_copyoutmap(MAP_T map, void * fromdata, vm_map_offset_t toaddr, vm_size_t length)
{
	if (will_copyio_panic_in_copy_validate(fromdata, length)) {
		return PANIC;
	}

	kern_return_t kr = copyoutmap(map, fromdata, toaddr, length);
	return kr;
}

static kern_return_t
call_vm_map_read_user(MAP_T map, vm_map_address_t src_addr, void * ptr, vm_size_t size)
{
	if (will_copyio_panic_in_copy_validate(ptr, size)) {
		return PANIC;
	}

	kern_return_t kr = vm_map_read_user(map, src_addr, ptr, size);
	return kr;
}

static kern_return_t
call_vm_map_write_user(MAP_T map, void * ptr, vm_map_address_t dst_addr, vm_size_t size)
{
	if (will_copyio_panic_in_copy_validate(ptr, size)) {
		return PANIC;
	}

	kern_return_t kr = vm_map_write_user(map, ptr, dst_addr, size);
	return kr;
}

static kern_return_t
call_vm_map_copy_overwrite_interruptible(MAP_T dst_map, vm_map_copy_t copy, mach_vm_address_t dst_addr, mach_vm_size_t copy_size)
{
	kern_return_t kr = vm_map_copy_overwrite(dst_map, dst_addr, copy, copy_size, TRUE);

	const mach_vm_size_t va_mask = ((1ULL << 48) - 1);
	if ((dst_addr & ~va_mask) == 0ULL && ((dst_addr + copy_size) & ~va_mask) == ~va_mask) {
		if (kr == KERN_INVALID_ADDRESS) {
			return ACCEPTABLE;
		}
	}
	return kr;
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

/*
 * VME_OFFSET_SET will panic due to an assertion if passed an address that is not aligned to VME_ALIAS_BITS
 * VME_OFFSET_SET is called by _vm_map_clip_(start/end)
 * vm_map_protect -> vm_map_clip_end -> _vm_map_clip_end -> VME_OFFSET_SET
 */
static bool
will_vm_map_protect_panic(mach_vm_address_t start, mach_vm_address_t end)
{
	bool start_aligned = start == ((start >> VME_ALIAS_BITS) << VME_ALIAS_BITS);
	bool end_aligned = end == ((end >> VME_ALIAS_BITS) << VME_ALIAS_BITS);
	return !(start_aligned && end_aligned);
}

static kern_return_t
call_vm_map_protect__start_size__no_max(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	mach_vm_address_t end = start + size;
	if (will_vm_map_protect_panic(start, end)) {
		return PANIC;
	}

	kern_return_t kr = vm_map_protect(map, start, end, 0, VM_PROT_READ | VM_PROT_WRITE);
	return kr;
}

static kern_return_t
call_vm_map_protect__start_size__set_max(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	mach_vm_address_t end = start + size;
	if (will_vm_map_protect_panic(start, end)) {
		return PANIC;
	}

	kern_return_t kr = vm_map_protect(map, start, end, 1, VM_PROT_READ | VM_PROT_WRITE);
	return kr;
}

static kern_return_t
call_vm_map_protect__vm_prot__no_max(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_prot_t prot)
{
	mach_vm_address_t end = start + size;
	if (will_vm_map_protect_panic(start, end)) {
		return PANIC;
	}

	kern_return_t kr = vm_map_protect(map, start, end, 0, prot);
	return kr;
}

static kern_return_t
call_vm_map_protect__vm_prot__set_max(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_prot_t prot)
{
	mach_vm_address_t end = start + size;
	if (will_vm_map_protect_panic(start, end)) {
		return PANIC;
	}

	kern_return_t kr = vm_map_protect(map, start, end, 0, prot);
	return kr;
}

// Fwd decl to avoid including bsd headers
int     useracc(user_addr_t addr, user_size_t len, int prot);

static int
call_useracc__start_size(void * start, size_t size)
{
	int result = useracc((user_addr_t) start, (user_addr_t) size, VM_PROT_READ);
	return result;
}

static int
call_useracc__vm_prot(void * start, size_t size, int prot)
{
	return useracc((user_addr_t) start, (user_addr_t) size, prot);
}

static int
call_vm_map_purgable_control__address__get(MAP_T map, mach_vm_address_t addr)
{
	int state = INVALID_PURGABLE_STATE;
	int initial_state = state;
	kern_return_t kr = vm_map_purgable_control(map, addr, VM_PURGABLE_GET_STATE, &state);
	check_mach_vm_purgable_control_outparam_changes(&kr, state, initial_state, VM_PURGABLE_GET_STATE);
	return kr;
}

static int
call_vm_map_purgable_control__address__purge_all(MAP_T map, mach_vm_address_t addr)
{
	int state = INVALID_PURGABLE_STATE;
	int initial_state = state;
	kern_return_t kr = vm_map_purgable_control(map, addr, VM_PURGABLE_PURGE_ALL, &state);
	check_mach_vm_purgable_control_outparam_changes(&kr, state, initial_state, VM_PURGABLE_PURGE_ALL);
	return kr;
}

static int
call_vm_map_purgable_control__purgeable_state(MAP_T map, vm_address_t addr, vm_purgable_t control, int state)
{
	int state_copy = state;
	kern_return_t kr = vm_map_purgable_control(map, addr, control, &state_copy);
	check_mach_vm_purgable_control_outparam_changes(&kr, state_copy, state, control);

	return kr;
}

#if XNU_PLATFORM_MacOSX
static void
check_vm_region_object_create_outparam_changes(kern_return_t * kr, ipc_port_t handle)
{
	if (handle == NULL) {
		*kr = OUT_PARAM_BAD;
	}
}

static kern_return_t
call_vm_region_object_create(MAP_T map, vm_size_t size)
{
	ipc_port_t handle = NULL;
	kern_return_t kr = vm_region_object_create(map, size, &handle);
	check_vm_region_object_create_outparam_changes(&kr, handle);

	if (kr == KERN_SUCCESS) {
		mach_memory_entry_port_release(handle);
	}

	return kr;
}
#endif /* #if XNU_PLATFORM_MacOSX */

static kern_return_t
call_vm_map_page_info(MAP_T map, mach_vm_address_t addr)
{
	vm_page_info_flavor_t flavor = VM_PAGE_INFO_BASIC;
	mach_msg_type_number_t count = VM_PAGE_INFO_BASIC_COUNT;
	mach_msg_type_number_t saved_count = count;
	vm_page_info_basic_data_t info = {0};
	info.depth = -1;
	vm_page_info_basic_data_t saved_info = info;

	/*
	 * If this test is invoked from a rosetta process,
	 * vm_map_page_range_info_internal doesn't know what
	 * effective_page_shift to use and returns KERN_INVALID_ARGUMENT.
	 * To fix this, we can set the region_page_shift to the page_shift
	 * used for map
	 */
	int saved_page_shift = thread_self_region_page_shift();
	if (PAGE_SIZE == KB16) {
		if (VM_MAP_PAGE_SHIFT(current_map()) != VM_MAP_PAGE_SHIFT(map)) {
			thread_self_region_page_shift_set(VM_MAP_PAGE_SHIFT(map));
		}
	}

	kern_return_t kr = vm_map_page_info(map, addr, flavor, (vm_page_info_t)&info, &count);

	thread_self_region_page_shift_set(saved_page_shift);

	check_mach_vm_page_info_outparam_changes(&kr, info, saved_info, count, saved_count);

	return kr;
}

#if CONFIG_MAP_RANGES
static kern_return_t
call_mach_vm_range_create(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, mach_vm_address_t second_start, mach_vm_size_t second_size)
{
	mach_vm_range_recipe_v1_t array[2];
	array[0] = (mach_vm_range_recipe_v1_t){
		.range = { start, start + size }, .range_tag = MACH_VM_RANGE_FIXED,
	};
	array[1] = (mach_vm_range_recipe_v1_t){
		.range = { second_start, second_start + second_size }, .range_tag = MACH_VM_RANGE_FIXED,
	};

	// mach_vm_range_create requires map == current_map(). Patch it up, do the call, and then restore it.
	vm_map_t saved_map = swap_task_map(current_task(), current_thread(), map);

	kern_return_t kr = mach_vm_range_create(map, MACH_VM_RANGE_FLAVOR_V1, (mach_vm_range_recipes_raw_t)array, sizeof(array[0]) * 2);

	swap_task_map(current_task(), current_thread(), saved_map);

	return kr;
}
#endif /* CONFIG_MAP_RANGES */

// Mach memory entry ownership

extern kern_return_t
mach_memory_entry_ownership(
	ipc_port_t      entry_port,
	task_t          owner,
	int             ledger_tag,
	int             ledger_flags);

static kern_return_t
call_mach_memory_entry_ownership__ledger_tag(MAP_T map __unused, int ledger_tag)
{
	mach_port_t mementry = make_a_mem_entry(map, TEST_ALLOC_SIZE + 1);
	kern_return_t kr = mach_memory_entry_ownership(mementry, TASK_NULL, ledger_tag, 0);
	mach_memory_entry_port_release(mementry);
	return kr;
}

static kern_return_t
call_mach_memory_entry_ownership__ledger_flag(MAP_T map __unused, int ledger_flag)
{
	mach_port_t mementry = make_a_mem_entry(map, TEST_ALLOC_SIZE + 1);
	kern_return_t kr = mach_memory_entry_ownership(mementry, TASK_NULL, VM_LEDGER_TAG_DEFAULT, ledger_flag);
	mach_memory_entry_port_release(mementry);
	return kr;
}

static inline void
check_mach_memory_entry_map_size_outparam_changes(kern_return_t * kr, mach_vm_size_t map_size,
    mach_vm_size_t invalid_initial_size)
{
	if (*kr == KERN_SUCCESS) {
		if (map_size == invalid_initial_size) {
			*kr = OUT_PARAM_BAD;
		}
	} else {
		if (map_size != 0) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

static kern_return_t
call_mach_memory_entry_map_size__start_size(MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	mach_port_t mementry;
	mach_vm_address_t addr;
	memory_object_size_t s = (memory_object_size_t)TEST_ALLOC_SIZE + 1;
	/*
	 * UNLIKELY_INITIAL_SIZE is guaranteed to never be the correct map_size
	 * from the mach_memory_entry_map_size calls we make. map_size should represent the size of the
	 * copy that would result, and UNLIKELY_INITIAL_SIZE is completely unrelated to the sizes we pass
	 * and not page aligned.
	 */
	mach_vm_size_t invalid_initial_size = UNLIKELY_INITIAL_SIZE;

	mach_vm_size_t map_size = invalid_initial_size;

	kern_return_t kr = mach_vm_allocate_kernel(map, &addr, s, FLAGS_AND_TAG(VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_OSFMK));
	assert(kr == 0);
	kr = mach_make_memory_entry_64(map, &s, (memory_object_offset_t)addr, MAP_MEM_VM_SHARE, &mementry, MACH_PORT_NULL);
	assert(kr == 0);
	kr = mach_memory_entry_map_size(mementry, map, start, size, &map_size);
	check_mach_memory_entry_map_size_outparam_changes(&kr, map_size, invalid_initial_size);
	mach_memory_entry_port_release(mementry);
	(void)mach_vm_deallocate(map, addr, s);
	return kr;
}

struct file_control_return {
	void * control;
	void * fp;
	void * vp;
	int fd;
};
struct file_control_return get_control_from_fd(int fd);
void cleanup_control_related_data(struct file_control_return info);
uint32_t vnode_vid(void * vp);

static void
check_task_find_region_details_outparam_changes(int * result,
    uintptr_t vp, uintptr_t saved_vp,
    uint32_t vid,
    bool is_map_shared,
    uint64_t start, uint64_t saved_start,
    uint64_t len, uint64_t saved_len)
{
	// task_find_region_details returns a bool. 0 means failure, 1 success
	if (*result == 0) {
		if (vp != 0 || vid != 0 || is_map_shared != 0 || start != 0 || len != 0) {
			*result = OUT_PARAM_BAD;
		}
	} else {
		if (vp == saved_vp || start == saved_start || len == saved_len) {
			*result = OUT_PARAM_BAD;
		}
		if (vid != (uint32_t)vnode_vid((void *)vp)) {
			*result = OUT_PARAM_BAD;
		}
		// is_map_shared seems to check if the relevant entry is shadowed by another
		// we don't set up any shadow entries for this test
		if (is_map_shared) {
			// *result = OUT_PARAM_BAD;
		}
	}
}


static int
call_task_find_region_details(MAP_T map, mach_vm_address_t addr)
{
	(void) map;
	uint64_t len = UNLIKELY_INITIAL_SIZE, start = UNLIKELY_INITIAL_ADDRESS;
	uint64_t saved_len = len, saved_start = start;
	bool is_map_shared = true;
	uintptr_t vp = (uintptr_t) INVALID_VNODE_PTR;
	uintptr_t saved_vp = vp;
	uint32_t vid = UNLIKELY_INITIAL_VID;

	/*
	 * task_find_region_details operates on task->map. Our setup code does allocations
	 * that otherwise could theoretically overwrite existing ones, so we don't want to
	 * operate on current_map
	 */
	vm_map_t saved_map = swap_task_map(current_task(), current_thread(), map);

	int kr = task_find_region_details(current_task(), addr, FIND_REGION_DETAILS_AT_OFFSET, &vp, &vid, &is_map_shared, &start, &len);

	swap_task_map(current_task(), current_thread(), saved_map);

	check_task_find_region_details_outparam_changes(&kr, vp, saved_vp, vid, is_map_shared, start, saved_start, len, saved_len);
	return kr;
}

static results_t * __attribute__((used))
test_kext_unix_with_allocated_vnode_addr(kern_return_t (*func)(MAP_T dst_map, mach_vm_address_t start), const char *testname)
{
	MAP_T map SMART_MAP;
	allocation_t base SMART_ALLOCATE_VM(map, TEST_ALLOC_SIZE, VM_PROT_DEFAULT);
	addr_trials_t *trials SMART_ADDR_TRIALS(base.addr);
	results_t *results = alloc_results(testname, eSMART_ADDR_TRIALS, base.addr, trials->count);

	for (unsigned i = 0; i < trials->count; i++) {
		mach_vm_address_t addr = (mach_vm_address_t)trials->list[i].addr;

		struct file_control_return control_info = get_control_from_fd(file_descriptor);
		vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_FIXED(.vmf_overwrite = true);
		kern_return_t kr = vm_map_enter_mem_object_control(map, &addr, TEST_ALLOC_SIZE, 0, vmk_flags, (memory_object_control_t) control_info.control, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
		if (kr == KERN_INVALID_ARGUMENT) {
			// can't map a file at that address, so we can't pass
			// such a mapping to the function being tested
			append_result(results, IGNORED, trials->list[i].name);
			cleanup_control_related_data(control_info);
			continue;
		}
		assert(kr == KERN_SUCCESS);

		kern_return_t ret = func(map, addr);
		append_result(results, ret, trials->list[i].name);
		cleanup_control_related_data(control_info);
	}
	return results;
}

extern uint64_t vm_reclaim_max_threshold;

#if 0
static kern_return_t
test_mach_vm_deferred_reclamation_buffer_init(MAP_T map __unused, mach_vm_address_t address, mach_vm_size_t size)
{
	uint64_t vm_reclaim_max_threshold_orig = vm_reclaim_max_threshold;
	kern_return_t kr = 0;

	vm_reclaim_max_threshold = KB16;
	kr = call_mach_vm_deferred_reclamation_buffer_init(current_task(), address, size);
	vm_reclaim_max_threshold = vm_reclaim_max_threshold_orig;

	return kr;
}
#endif


// mach_make_memory_entry and variants

static inline void
check_mach_memory_entry_outparam_changes(kern_return_t * kr, mach_vm_size_t size,
    mach_port_t out_handle)
{
	/*
	 * mach_make_memory_entry overwrites *size to be 0 on failure.
	 */
	if (*kr != KERN_SUCCESS) {
		if (size != 0) {
			*kr = OUT_PARAM_BAD;
		}
		if (out_handle != 0) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

#define IMPL(FN, T)                                                               \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__memonly(MAP_T map, T start, T size)                      \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_handle_value = UNLIKELY_INITIAL_MACH_PORT;     \
	        mach_port_t out_handle = invalid_handle_value;                    \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_ONLY, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                if (out_handle) mach_memory_entry_port_release(out_handle); \
	        }                                                                 \
	        mach_memory_entry_port_release(memobject);                        \
	        check_mach_memory_entry_outparam_changes(&kr, io_size, out_handle); \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__namedcreate(MAP_T map, T start, T size)                  \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_handle_value = UNLIKELY_INITIAL_MACH_PORT;     \
	        mach_port_t out_handle = invalid_handle_value;                    \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_NAMED_CREATE, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                if (out_handle) mach_memory_entry_port_release(out_handle); \
	        }                                                                 \
	        mach_memory_entry_port_release(memobject);                        \
	        check_mach_memory_entry_outparam_changes(&kr, io_size, out_handle); \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__copy(MAP_T map, T start, T size)                         \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_handle_value = UNLIKELY_INITIAL_MACH_PORT;     \
	        mach_port_t out_handle = invalid_handle_value;                    \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_VM_COPY, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                if (out_handle) mach_memory_entry_port_release(out_handle); \
	        }                                                                 \
	        mach_memory_entry_port_release(memobject);                        \
	        check_mach_memory_entry_outparam_changes(&kr, io_size, out_handle); \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__share(MAP_T map, T start, T size)            \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_handle_value = UNLIKELY_INITIAL_MACH_PORT;     \
	        mach_port_t out_handle = invalid_handle_value;                    \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_VM_SHARE, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                if (out_handle) mach_memory_entry_port_release(out_handle); \
	        }                                                                 \
	        mach_memory_entry_port_release(memobject);                        \
	        check_mach_memory_entry_outparam_changes(&kr, io_size, out_handle); \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__namedreuse(MAP_T map, T start, T size)       \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_handle_value = UNLIKELY_INITIAL_MACH_PORT;     \
	        mach_port_t out_handle = invalid_handle_value;                    \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_NAMED_REUSE, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                if (out_handle) mach_memory_entry_port_release(out_handle); \
	        }                                                                 \
	        mach_memory_entry_port_release(memobject);                        \
	        check_mach_memory_entry_outparam_changes(&kr, io_size, out_handle); \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __vm_prot(MAP_T map, T start, T size, vm_prot_t prot)      \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_handle_value = UNLIKELY_INITIAL_MACH_PORT;     \
	        mach_port_t out_handle = invalid_handle_value;                    \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              prot, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                if (out_handle) mach_memory_entry_port_release(out_handle); \
	        }                                                                 \
	        mach_memory_entry_port_release(memobject);                        \
	        check_mach_memory_entry_outparam_changes(&kr, io_size, out_handle); \
	        return kr;                                                        \
	}

IMPL(mach_make_memory_entry_64, mach_vm_address_t)
IMPL(mach_make_memory_entry, vm_size_t)
static kern_return_t
mach_make_memory_entry_internal_retyped(
	vm_map_t                target_map,
	memory_object_size_t    *size,
	memory_object_offset_t  offset,
	vm_prot_t               permission,
	ipc_port_t              *object_handle,
	ipc_port_t              parent_handle)
{
	vm_named_entry_kernel_flags_t   vmne_kflags = VM_NAMED_ENTRY_KERNEL_FLAGS_NONE;
	if (permission & MAP_MEM_LEDGER_TAGGED) {
		vmne_kflags.vmnekf_ledger_tag = VM_LEDGER_TAG_DEFAULT;
	}
	return mach_make_memory_entry_internal(target_map, size, offset, permission, vmne_kflags, object_handle, parent_handle);
}
IMPL(mach_make_memory_entry_internal_retyped, mach_vm_address_t)

#undef IMPL

// mach_vm_map/mach_vm_map_external/mach_vm_map_kernel/vm_map/vm_map_external infra

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
	// fixed-overwrite with pre-existing allocation, don't deallocate
	mach_memory_entry_port_release(memobject);
	return kr;
}

static kern_return_t
call_map_fn__memobject_fixed_copy(map_fn_t fn, MAP_T map, mach_vm_address_t start, mach_vm_size_t size)
{
	mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);
	mach_vm_address_t out_addr = start;
	kern_return_t kr = fn(map, &out_addr, size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
	    memobject, KB16, true, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	// fixed-overwrite with pre-existing allocation, don't deallocate
	mach_memory_entry_port_release(memobject);
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
	mach_memory_entry_port_release(memobject);
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
	mach_memory_entry_port_release(memobject);
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
	mach_memory_entry_port_release(memobject);
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
	mach_memory_entry_port_release(memobject);
	return kr;
}

static kern_return_t
call_map_fn__memobject_copy__flags(map_fn_t fn, MAP_T map, mach_vm_address_t * start, mach_vm_size_t size, int flags)
{
	mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);
	kern_return_t kr = fn(map, start, size, 0, flags,
	    memobject, KB16, true, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	deallocate_if_not_fixed_overwrite(kr, map, *start, size, flags);
	mach_memory_entry_port_release(memobject);
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
	mach_memory_entry_port_release(memobject);
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

// wrappers

kern_return_t
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
	if (dealloc_would_time_out(*address, size, target_task)) {
		return ACCEPTABLE;
	}

	mach_vm_address_t saved_addr = *address;
	kern_return_t kr = mach_vm_map(target_task, address, size, mask, flags, object, offset, copy, cur_protection, max_protection, inheritance);
	check_mach_vm_map_outparam_changes(&kr, *address, saved_addr, flags, target_task);
	return kr;
}

// missing forward declaration
kern_return_t
mach_vm_map_external(
	vm_map_t                target_map,
	mach_vm_offset_t        *address,
	mach_vm_size_t          initial_size,
	mach_vm_offset_t        mask,
	int                     flags,
	ipc_port_t              port,
	vm_object_offset_t      offset,
	boolean_t               copy,
	vm_prot_t               cur_protection,
	vm_prot_t               max_protection,
	vm_inherit_t            inheritance);
kern_return_t
mach_vm_map_external_wrapped(vm_map_t target_task,
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
	if (dealloc_would_time_out(*address, size, target_task)) {
		return ACCEPTABLE;
	}

	mach_vm_address_t saved_addr = *address;
	kern_return_t kr = mach_vm_map_external(target_task, address, size, mask, flags, object, offset, copy, cur_protection, max_protection, inheritance);
	check_mach_vm_map_outparam_changes(&kr, *address, saved_addr, flags, target_task);
	return kr;
}

kern_return_t
mach_vm_map_kernel_wrapped(vm_map_t target_task,
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
	if (dealloc_would_time_out(*address, size, target_task)) {
		return ACCEPTABLE;
	}

	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;

	vm_map_kernel_flags_set_vmflags(&vmk_flags, flags);
	mach_vm_address_t saved_addr = *address;
	kern_return_t kr = mach_vm_map_kernel(target_task, address, size, mask, vmk_flags, object, offset, copy, cur_protection, max_protection, inheritance);
	check_mach_vm_map_outparam_changes(&kr, *address, saved_addr, flags, target_task);
	return kr;
}

static inline void
check_vm_map_enter_mem_object_control_outparam_changes(kern_return_t * kr, mach_vm_address_t addr,
    mach_vm_address_t saved_start, int flags, MAP_T map)
{
	if (*kr == KERN_SUCCESS) {
		if (is_fixed(flags)) {
			if (addr != truncate_vm_map_addr_with_flags(map, saved_start, flags)) {
				*kr = OUT_PARAM_BAD;
			}
		}
	} else {
		if (saved_start != addr) {
			*kr = OUT_PARAM_BAD;
		}
	}
}

kern_return_t
vm_map_enter_mem_object_control_wrapped(
	vm_map_t                target_map,
	mach_vm_address_t      *address,
	mach_vm_size_t          size,
	vm_map_offset_t         mask,
	int                     flags,
	mem_entry_name_port_t   object __unused,
	memory_object_offset_t  offset,
	boolean_t               copy,
	vm_prot_t               cur_protection,
	vm_prot_t               max_protection,
	vm_inherit_t            inheritance)
{
	if (dealloc_would_time_out(*address, size, target_map)) {
		return ACCEPTABLE;
	}

	vm_map_offset_t vmmaddr = (vm_map_offset_t) *address;
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;

	vm_map_kernel_flags_set_vmflags(&vmk_flags, flags);
	struct file_control_return control_info = get_control_from_fd(file_descriptor);
	kern_return_t kr = vm_map_enter_mem_object_control(target_map, &vmmaddr, size, mask, vmk_flags, (memory_object_control_t) control_info.control, offset, copy, cur_protection, max_protection, inheritance);
	check_vm_map_enter_mem_object_control_outparam_changes(&kr, vmmaddr, *address, flags, target_map);

	*address = vmmaddr;

	cleanup_control_related_data(control_info);

	return kr;
}

kern_return_t
vm_map_wrapped(vm_map_t target_task,
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
	if (dealloc_would_time_out(*address, size, target_task)) {
		return ACCEPTABLE;
	}

	vm_address_t addr = (vm_address_t)*address;
	kern_return_t kr = vm_map(target_task, &addr, size, mask, flags, object, offset, copy, cur_protection, max_protection, inheritance);
	check_mach_vm_map_outparam_changes(&kr, addr, (vm_address_t)*address, flags, target_task);
	*address = addr;
	return kr;
}

kern_return_t
vm_map_external(
	vm_map_t                target_map,
	vm_offset_t             *address,
	vm_size_t               size,
	vm_offset_t             mask,
	int                     flags,
	ipc_port_t              port,
	vm_offset_t             offset,
	boolean_t               copy,
	vm_prot_t               cur_protection,
	vm_prot_t               max_protection,
	vm_inherit_t            inheritance);
kern_return_t
vm_map_external_wrapped(vm_map_t target_task,
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
	if (dealloc_would_time_out(*address, size, target_task)) {
		return ACCEPTABLE;
	}

	vm_address_t addr = (vm_address_t)*address;
	kern_return_t kr = vm_map_external(target_task, &addr, size, mask, flags, object, offset, copy, cur_protection, max_protection, inheritance);
	check_mach_vm_map_outparam_changes(&kr, addr, (vm_address_t)*address, flags, target_task);
	*address = addr;
	return kr;
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

IMPL(mach_vm_map_wrapped)
IMPL(mach_vm_map_external_wrapped)
IMPL(mach_vm_map_kernel_wrapped)
IMPL(vm_map_wrapped)
IMPL(vm_map_external_wrapped)
IMPL(vm_map_enter_mem_object_control_wrapped)

#undef IMPL

static int
vm_parameter_validation_kern_test(int64_t in_value, int64_t *out_value)
{
	// in_value has the userspace address of the fixed-size output buffer and a file descriptor.
	// The address is KB16 aligned, so the bottom bits are used for the fd.
	// fd bit 15 also indicates if we want to generate golden results.
	// in_value is KB16 aligned
	uint64_t fd_mask = KB16 - 1;
	file_descriptor = (int)(((uint64_t) in_value) & fd_mask);
	uint64_t buffer_address = in_value - file_descriptor;
	SYSCTL_OUTPUT_BUF = buffer_address;
	SYSCTL_OUTPUT_END = SYSCTL_OUTPUT_BUF + SYSCTL_OUTPUT_BUFFER_SIZE;

	// check if running to generate golden result list via boot-arg
	kernel_generate_golden = (file_descriptor & (KB16 >> 1)) > 0;
	if (kernel_generate_golden) {
		file_descriptor &= ~(KB16 >> 1);
	}

	// Test options:
	// - avoid panics for untagged wired memory (set to true during some tests)
	// - clamp vm addresses before passing to pmap to avoid pmap panics
	thread_test_context_t ctx CLEANUP_THREAD_TEST_CONTEXT = {
		.test_option_vm_prevent_wire_tag_panic = false,
		.test_option_vm_map_clamp_pmap_remove = true,
	};
	thread_set_test_context(&ctx);

#if !CONFIG_SPTM && (__ARM_42BIT_PA_SPACE__ || ARM_LARGE_MEMORY)
	if (kernel_generate_golden) {
		// Some devices skip some trials to avoid timeouts.
		// Golden files cannot be generated on these devices.
		testprintf("Can't generate golden files on this device "
		    "(PPL && (__ARM_42BIT_PA_SPACE__ || ARM_LARGE_MEMORY)). "
		    "Try again on a different device.\n");
		*out_value = 0;  // failure
		goto done;
	}
#else
#pragma clang diagnostic ignored "-Wunused-label"
#endif

	/*
	 * -- memory entry functions --
	 * The memory entry test functions use macros to generate each flavor of memory entry function.
	 * For more context on why, see the matching comment in vm_parameter_validation.c
	 */

#define RUN_START_SIZE(fn, variant, name) dealloc_results(process_results(test_mach_with_allocated_start_size(call_ ## fn ## __start_size__ ## variant, name " (start/size)")))
#define RUN_PROT(fn, name) dealloc_results(process_results(test_mach_with_allocated_vm_prot_t(call_ ## fn ## __vm_prot , name " (vm_prot_t)")))

#define RUN_ALL(fn, name) \
	RUN_START_SIZE(fn, copy, #name " (copy)"); \
	RUN_START_SIZE(fn, memonly, #name " (memonly)"); \
	RUN_START_SIZE(fn, namedcreate, #name " (namedcreate)"); \
	RUN_START_SIZE(fn, share, #name " (share)"); \
	RUN_START_SIZE(fn, namedreuse, #name " (namedreuse)"); \
	RUN_PROT(fn, #name " (vm_prot_t)"); \

	RUN_ALL(mach_make_memory_entry_64, mach_make_memory_entry_64);
	RUN_ALL(mach_make_memory_entry, mach_make_memory_entry);
	RUN_ALL(mach_make_memory_entry_internal_retyped, mach_make_memory_entry_internal);
#undef RUN_ALL
#undef RUN_START_SIZE
#undef RUN_PROT

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_ledger_tag(fn, name " (ledger tag)")))
	RUN(call_mach_memory_entry_ownership__ledger_tag, "mach_memory_entry_ownership");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_ledger_flag(fn, name " (ledger flag)")))
	RUN(call_mach_memory_entry_ownership__ledger_flag, "mach_memory_entry_ownership");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_mach_memory_entry_map_size__start_size, "mach_memory_entry_map_size");
#undef RUN

	/*
	 * -- allocate/deallocate functions --
	 */

#define RUN(fn, name) dealloc_results(process_results(test_mach_allocation_func_with_start_size(fn, name)))
	RUN(call_mach_vm_allocate__start_size_fixed, "mach_vm_allocate_external (fixed) (realigned start/size)");
	RUN(call_mach_vm_allocate__start_size_anywhere, "mach_vm_allocate_external (anywhere) (hint/size)");
	RUN(call_mach_vm_allocate_kernel__start_size_fixed, "mach_vm_allocate (fixed) (realigned start/size)");
	RUN(call_mach_vm_allocate_kernel__start_size_anywhere, "mach_vm_allocate (anywhere) (hint/size)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_allocation_func_with_vm_map_kernel_flags_t(fn, name " (vm_map_kernel_flags_t)")))
	RUN(call_mach_vm_allocate__flags, "mach_vm_allocate_external");
	RUN(call_mach_vm_allocate_kernel__flags, "mach_vm_allocate_kernel");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_allocation_func_with_start_size(fn, name)))
	RUN(call_vm_allocate__start_size_fixed, "vm_allocate (fixed) (realigned start/size)");
	RUN(call_vm_allocate__start_size_anywhere, "vm_allocate (anywhere) (hint/size)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_allocation_func_with_vm_map_kernel_flags_t(fn, name " (vm_map_kernel_flags_t)")))
	RUN(call_vm_allocate__flags, "vm_allocate");
#undef RUN
	dealloc_results(process_results(test_deallocator(call_mach_vm_deallocate, "mach_vm_deallocate (start/size)")));
	dealloc_results(process_results(test_deallocator(call_vm_deallocate, "vm_deallocate (start/size)")));

	/*
	 * -- map/remap functions --
	 * These functions rely heavily on macros.
	 * For more context on why, see the matching comment in vm_parameter_validation.c
	 */

	// map tests

#define RUN_START_SIZE(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (realigned start/size)")))
#define RUN_HINT_SIZE(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (hint/size)")))
#define RUN_PROT_PAIR(fn, name) dealloc_results(process_results(test_mach_vm_prot_pair(fn, name " (vm_prot_t pair)")))
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
	RUN_ALL(mach_vm_map_external_wrapped, mach_vm_map_external);
	RUN_ALL(mach_vm_map_kernel_wrapped, mach_vm_map_kernel);
	RUN_ALL(vm_map_wrapped, vm_map);
	RUN_ALL(vm_map_external_wrapped, vm_map_external);

#define RUN_SSO(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size_offset(fn, name " (start/size/offset)")))

#define RUN_ALL_CTL(fn, name)     \
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
	RUN_SSO(call_ ## fn ## __memobject_fixed__start_size_offset_object, #name " (memobject fixed overwrite)");  \
	RUN_SSO(call_ ## fn ## __memobject_fixed_copy__start_size_offset_object, #name " (memobject fixed overwrite copy)");  \
	RUN_SSO(call_ ## fn ## __memobject_anywhere__start_size_offset_object, #name " (memobject anywhere)");  \

	RUN_ALL_CTL(vm_map_enter_mem_object_control_wrapped, vm_map_enter_mem_object_control);

#undef RUN_ALL
#undef RUN_START_SIZE
#undef RUN_HINT_SIZE
#undef RUN_PROT_PAIR
#undef RUN_INHERIT
#undef RUN_FLAGS
#undef RUN_SSOO
#undef RUN_ALL_CTL
#undef RUN_SSO

	// remap tests

#define FN_NAME(fn, variant, type) call_ ## fn ## __  ## variant ## __ ## type
#define RUN_HELPER(harness, fn, variant, type, type_name, name) dealloc_results(process_results(harness(FN_NAME(fn, variant, type), #name " (" #variant ") (" type_name ")")))
#define RUN_SRC_SIZE(fn, variant, type_name, name) RUN_HELPER(test_mach_with_allocated_start_size, fn, variant, src_size, type_name, name)
#define RUN_DST_SIZE(fn, variant, type_name, name) RUN_HELPER(test_mach_with_allocated_start_size, fn, variant, dst_size, type_name, name)
#define RUN_PROT_PAIRS(fn, variant, name) RUN_HELPER(test_mach_with_allocated_vm_prot_pair, fn, variant, prot_pairs, "prot_pairs", name)
#define RUN_INHERIT(fn, variant, name) RUN_HELPER(test_mach_with_allocated_vm_inherit_t, fn, variant, inherit, "inherit", name)
#define RUN_FLAGS(fn, variant, name) RUN_HELPER(test_mach_with_allocated_vm_map_kernel_flags_t, fn, variant, flags, "flags", name)
#define RUN_SRC_DST_SIZE(fn, variant, type_name, name) RUN_HELPER(test_allocated_src_unallocated_dst_size, fn, variant, src_dst_size, type_name, name)

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
	RUN_SRC_DST_SIZE(fn, fixed, "src/dst/size", name);              \
	RUN_SRC_DST_SIZE(fn, fixed_copy, "src/dst/size", name);         \
	RUN_SRC_DST_SIZE(fn, anywhere, "src/dst/size", name);           \

	RUN_ALL(mach_vm_remap_wrapped_kern, "realigned ", mach_vm_remap);
	RUN_ALL(mach_vm_remap_new_kernel_wrapped, , mach_vm_remap_new_kernel);

#undef RUN_ALL
#undef RUN_HELPER
#undef RUN_SRC_SIZE
#undef RUN_DST_SIZE
#undef RUN_PROT_PAIRS
#undef RUN_INHERIT
#undef RUN_FLAGS
#undef RUN_SRC_DST_SIZE

	/*
	 * -- wire/unwire functions --
	 * Some wire functions (vm_map_wire_and_extract, vm_map_wire_external, vm_map_wire_kernel)
	 * are implemented with macros to avoid code duplication that would happen otherwise from the multiple
	 * entrypoints, multiple params under test, and user/non user wired paths
	 */

#define RUN(fn, name) dealloc_results(process_results(test_kext_unix_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_vslock, "vslock");
	RUN(call_vsunlock_undirtied, "vsunlock (undirtied)");
	RUN(call_vsunlock_dirtied, "vsunlock (dirtied)");
#undef RUN

#define RUN_PROT(fn, wired, name) dealloc_results(process_results(test_mach_with_allocated_vm_prot_t(call_ ## fn ## __prot__user_wired_ ## wired ## _, name " (vm_prot_t)")))
#define RUN_START(fn, wired, name) dealloc_results(process_results(test_kext_tagged_with_allocated_addr(call_ ## fn ## __start__user_wired_ ## wired ## _, name " (addr)")))
#define RUN_START_END(fn, wired, name) dealloc_results(process_results(test_mach_with_allocated_start_end(call_ ## fn ## __start_end__user_wired_ ## wired ## _, name " (start/end)")))
#define RUN_TAG(fn, wired, name) dealloc_results(process_results(test_mach_with_allocated_tag(call_ ## fn ## __tag__user_wired_ ## wired ## _, name " (tag)")))

#if XNU_PLATFORM_MacOSX
// vm_map_wire_and_extract is implemented on macOS only

#define RUN_ALL_WIRE_AND_EXTRACT(fn, name) \
	RUN_PROT(fn, true, #name " (user wired)"); \
	RUN_PROT(fn, false, #name " (non user wired)"); \
	RUN_START(fn, true, #name " (user wired)"); \
	RUN_START(fn, false, #name " (non user wired)");

	RUN_ALL_WIRE_AND_EXTRACT(vm_map_wire_and_extract_retyped, vm_map_wire_and_extract);
#undef RUN_ALL_WIRE_AND_EXTRACT
#endif // XNU_PLATFORM_MacOSX

#define RUN_ALL_WIRE_EXTERNAL(fn, name) \
	RUN_PROT(fn, true, #name " (user wired)"); \
	RUN_PROT(fn, false, #name " (non user wired))"); \
	RUN_START_END(fn, true, #name " (user wired)"); \
	RUN_START_END(fn, false, #name " (non user wired)");

	RUN_ALL_WIRE_EXTERNAL(vm_map_wire_external_retyped, vm_map_wire_external);
#undef RUN_ALL_WIRE_EXTERNAL

#define RUN_ALL_WIRE_KERNEL(fn, name) \
	RUN_PROT(fn, false, #name " (non user wired))"); \
	RUN_PROT(fn, true, #name " (user wired)"); \
	RUN_START_END(fn, true, #name " (user wired)"); \
	RUN_START_END(fn, false, #name " (non user wired)"); \
	RUN_TAG(fn, true, #name " (user wired)"); \
	RUN_TAG(fn, false, #name " (non user wired)");

	RUN_ALL_WIRE_KERNEL(vm_map_wire_kernel, vm_map_wire_kernel);
#undef RUN_ALL_WIRE_KERNEL

#undef RUN_PROT
#undef RUN_START
#undef RUN_START_END
#undef RUN_TAG

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_end(fn, name " (start/end)")))
	RUN(call_vm_map_unwire_user_wired, "vm_map_unwire (user_wired)");
	RUN(call_vm_map_unwire_non_user_wired, "vm_map_unwire (non user_wired)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_with_int64(fn, name " (int64)")))
	RUN(call_mach_vm_wire_level_monitor, "mach_vm_wire_level_monitor");
#undef RUN

	/*
	 * -- copyin/copyout functions --
	 */

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_vm_map_copyin, "vm_map_copyin");
	RUN(call_mach_vm_read, "mach_vm_read");
	// vm_map_copyin_common is covered well by the vm_map_copyin test
	// RUN(call_vm_map_copyin_common, "vm_map_copyin_common");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_addr_of_size_n(fn, sizeof(uint32_t), name " (start)")))
	RUN(call_copyoutmap_atomic32, "copyoutmap_atomic32");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_src_kerneldst_size(fn, name " (src/dst/size)")))
	RUN(call_copyinmap, "copyinmap");
	RUN(call_vm_map_read_user, "vm_map_read_user");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_kernelsrc_dst_size(fn, name " (src/dst/size)")))
	RUN(call_vm_map_write_user, "vm_map_write_user");
	RUN(call_copyoutmap, "copyoutmap");
#undef RUN

	dealloc_results(process_results(test_vm_map_copy_overwrite(call_vm_map_copy_overwrite_interruptible, "vm_map_copy_overwrite (start/size)")));

	/*
	 * -- protection functions --
	 */

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_mach_vm_protect__start_size, "mach_vm_protect");
	RUN(call_vm_protect__start_size, "vm_protect");
	RUN(call_vm_map_protect__start_size__no_max, "vm_map_protect (no max)");
	RUN(call_vm_map_protect__start_size__set_max, "vm_map_protect (set max)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
	RUN(call_mach_vm_protect__vm_prot, "mach_vm_protect");
	RUN(call_vm_protect__vm_prot, "vm_protect");
	RUN(call_vm_map_protect__vm_prot__no_max, "vm_map_protect (no max)");
	RUN(call_vm_map_protect__vm_prot__set_max, "vm_map_protect (set max)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_unix_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_useracc__start_size, "useracc");
#undef RUN
#define RUN(fn, name) dealloc_results(process_results(test_unix_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
	RUN(call_useracc__vm_prot, "useracc");
#undef RUN

	/*
	 * -- madvise/behavior functions --
	 */

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_mach_vm_behavior_set__start_size__default, "mach_vm_behavior_set (VM_BEHAVIOR_DEFAULT)");
	RUN(call_mach_vm_behavior_set__start_size__can_reuse, "mach_vm_behavior_set (VM_BEHAVIOR_CAN_REUSE)");
#undef RUN
#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_vm_behavior_t(fn, name " (vm_behavior_t)")))
	RUN(call_mach_vm_behavior_set__vm_behavior, "mach_vm_behavior_set");
#undef RUN

	/*
	 * -- purgability/purgeability functions --
	 */

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_purgeable_addr(fn, name " (addr)")))
	RUN(call_vm_map_purgable_control__address__get, "vm_map_purgable_control (get)");
	RUN(call_vm_map_purgable_control__address__purge_all, "vm_map_purgable_control (purge all)");
#undef RUN

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_purgeable_and_state(fn, name " (purgeable and state)")))
	RUN(call_vm_map_purgable_control__purgeable_state, "vm_map_purgable_control");
#undef RUN

	/*
	 * -- region info functions --
	 */

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_addr(fn, name " (addr)")))
	RUN(call_mach_vm_region, "mach_vm_region");
	RUN(call_vm_region, "vm_region");
#undef RUN
#if XNU_PLATFORM_MacOSX
#define RUN(fn, name) dealloc_results(process_results(test_mach_with_size(fn, name " (size)")))
	RUN(call_vm_region_object_create, "vm_region_object_create");
#undef RUN
#endif

	/*
	 * -- page info functions --
	 */

#define RUN(fn, name) dealloc_results(process_results(test_mach_with_allocated_addr(fn, name " (addr)")))
	RUN(call_vm_map_page_info, "vm_map_page_info");
#undef RUN

	/*
	 * -- miscellaneous functions --
	 */

#if CONFIG_MAP_RANGES
	dealloc_results(process_results(test_mach_vm_range_create(call_mach_vm_range_create, "mach_vm_range_create (start/size/start2/size2)")));
#endif

	dealloc_results(process_results(test_kext_unix_with_allocated_vnode_addr(call_task_find_region_details, "task_find_region_details (addr)")));

	*out_value = 1;  // success
done:
	SYSCTL_OUTPUT_BUF = 0;
	SYSCTL_OUTPUT_END = 0;
	return 0;
}

SYSCTL_TEST_REGISTER(vm_parameter_validation_kern, vm_parameter_validation_kern_test);
