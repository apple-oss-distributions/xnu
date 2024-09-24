#include <sys/cdefs.h>
#include <kern/zalloc.h>

#include "vm_parameter_validation.h"

#pragma clang diagnostic ignored "-Wdeclaration-after-statement"
#pragma clang diagnostic ignored "-Wincompatible-function-pointer-types"
#pragma clang diagnostic ignored "-Wmissing-prototypes"
#pragma clang diagnostic ignored "-Wpedantic"
#pragma clang diagnostic ignored "-Wgcc-compat"

#pragma clang diagnostic ignored "-Wunused-variable"


// Kernel sysctl test prints its output into a userspace buffer.
// fixme these global variables prevent test concurrency

static user_addr_t SYSCTL_OUTPUT_BUF;
static user_addr_t SYSCTL_OUTPUT_END;

// This is a read/write fd passed from userspace.
// It's passed to make it easier for kernel tests to interact with a file.
static int file_descriptor;

// Output to create a golden test result in kern test, controlled by
// vm_parameter_validation_kern_golden=1
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
	results_t *results = alloc_results(testname, trials->count);

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
	results_t *results = alloc_results(testname, trials->count);

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
	results_t *results = alloc_results(testname, trials->count);

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
	vm_map_copy_t invalid_initial_value = INVALID_INITIAL_COPY;
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
	mach_vm_address_t saved_start = *start;
	mach_vm_address_t minus_two_kb16 = -2 * KB16;

	if (*start + size >= minus_two_kb16) {
		// Allocation actually works fine here. Deallocation does not.
		// It triggers a end < start assertion in pmap. Seems like some offset is added to the end of the region, which is -KB16 in these cases which overflows.
		return PANIC;
	}
	mach_vm_address_t before = *start;

	kern_return_t kr = mach_vm_allocate_kernel(map, start, size,
	    FLAGS_AND_TAG(VM_FLAGS_FIXED, VM_KERN_MEMORY_OSFMK));
	check_mach_vm_allocate_outparam_changes(&kr, *start, size, saved_start, VM_FLAGS_FIXED, map);


	return kr;
}

static kern_return_t
call_mach_vm_allocate_kernel__start_size_anywhere(MAP_T map, mach_vm_address_t * start, mach_vm_size_t size)
{
	mach_vm_address_t saved_start = *start;
	mach_vm_address_t minus_two_kb16 = -2 * KB16;
	if (*start + size >= minus_two_kb16) {
		// Allocation actually works fine here. Deallocation does not.
		// It triggers a end < start assertion in pmap. Seems like some offset is added to the end of the region, which is -KB16 in these cases which overflows.
		return PANIC;
	}
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

#if XNU_PLATFORM_MacOSX
// vm_map_wire_and_extract() implemented on macOS only

static inline void
check_vm_map_wire_and_extract_out_params_changes(kern_return_t * kr, ppnum_t physpage)
{
	if (*kr != KERN_SUCCESS) {
		if (physpage != 0) {
			*kr = OUT_PARAM_BAD;
		}
	}
}


static kern_return_t
call_vm_map_wire_and_extract_user_wired(MAP_T map, mach_vm_address_t start)
{
	if (will_wire_function_panic_due_to_alignment(start, start + VM_MAP_PAGE_SIZE(map))) {
		return PANIC;
	}
	if (will_wire_function_panic_due_to_vm_tag(start)) {
		return BUSTED;
	}

	ppnum_t physpage = INVALID_INITIAL_PPNUM;
	kern_return_t kr = vm_map_wire_and_extract(map, start, VM_PROT_DEFAULT, TRUE, &physpage);
	check_vm_map_wire_and_extract_out_params_changes(&kr, physpage);
	return kr;
}

static kern_return_t
call_vm_map_wire_and_extract_non_user_wired(MAP_T map, mach_vm_address_t start)
{
	if (will_wire_function_panic_due_to_alignment(start, start + VM_MAP_PAGE_SIZE(map))) {
		return PANIC;
	}
	if (will_wire_function_panic_due_to_vm_tag(start)) {
		return BUSTED;
	}
	ppnum_t physpage = INVALID_INITIAL_PPNUM;
	kern_return_t kr = vm_map_wire_and_extract(map, start, VM_PROT_DEFAULT, FALSE, &physpage);
	check_vm_map_wire_and_extract_out_params_changes(&kr, physpage);
	return kr;
}

static kern_return_t
call_vm_map_wire_and_extract_vm_prot_t_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_prot_t prot)
{
	(void) size;
	if (will_wire_function_panic_due_to_alignment(start, start + VM_MAP_PAGE_SIZE(map))) {
		return PANIC;
	}
	if (will_wire_function_panic_due_to_vm_tag(start)) {
		return BUSTED;
	}

	ppnum_t physpage = INVALID_INITIAL_PPNUM;
	kern_return_t kr = vm_map_wire_and_extract(map, start, prot, TRUE, &physpage);
	check_vm_map_wire_and_extract_out_params_changes(&kr, physpage);
	return kr;
}

static kern_return_t
call_vm_map_wire_and_extract_vm_prot_t_non_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_prot_t prot)
{
	(void) size;
	if (will_wire_function_panic_due_to_alignment(start, start + VM_MAP_PAGE_SIZE(map))) {
		return PANIC;
	}
	if (will_wire_function_panic_due_to_vm_tag(start)) {
		return BUSTED;
	}

	ppnum_t physpage = INVALID_INITIAL_PPNUM;
	kern_return_t kr = vm_map_wire_and_extract(map, start, prot, FALSE, &physpage);
	check_vm_map_wire_and_extract_out_params_changes(&kr, physpage);
	return kr;
}

#endif // XNU_PLATFORM_MacOSX

extern kern_return_t    vm_map_wire_external(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vm_prot_t               access_type,
	boolean_t               user_wire);

static kern_return_t
call_vm_map_wire_external_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_address_t end)
{
	if (will_wire_function_panic_due_to_alignment(start, end)) {
		return PANIC;
	}
	if (will_wire_function_panic_due_to_vm_tag(start)) {
		return BUSTED;
	}

	kern_return_t kr = vm_map_wire_external(map, start, end, VM_PROT_DEFAULT, TRUE);
	return kr;
}

static kern_return_t
call_vm_map_wire_external_non_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_address_t end)
{
	if (will_wire_function_panic_due_to_alignment(start, end)) {
		return PANIC;
	}
	if (will_wire_function_panic_due_to_vm_tag(start)) {
		return BUSTED;
	}

	kern_return_t kr = vm_map_wire_external(map, start, end, VM_PROT_DEFAULT, FALSE);
	if (kr == KERN_SUCCESS) {
		(void) vm_map_unwire(map, start, end, FALSE);
	}
	return kr;
}

static kern_return_t
call_vm_map_wire_kernel_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_address_t end)
{
	if (will_wire_function_panic_due_to_alignment(start, end)) {
		return PANIC;
	}
	kern_return_t kr = vm_map_wire_kernel(map, start, end, VM_PROT_DEFAULT, VM_KERN_MEMORY_OSFMK, TRUE);
	return kr;
}

static kern_return_t
call_vm_map_wire_kernel_non_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_address_t end)
{
	if (will_wire_function_panic_due_to_alignment(start, end)) {
		return PANIC;
	}
	kern_return_t kr = vm_map_wire_kernel(map, start, end, VM_PROT_DEFAULT, VM_KERN_MEMORY_OSFMK, FALSE);
	if (kr == KERN_SUCCESS) {
		(void) vm_map_unwire(map, start, end, FALSE);
	}
	return kr;
}

static kern_return_t
call_vm_map_wire_external_vm_prot_t_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_prot_t prot)
{
	mach_vm_address_t end;
	if (__builtin_add_overflow(start, size, &end)) {
		return BUSTED;
	}

	if (will_wire_function_panic_due_to_alignment(start, end)) {
		return PANIC;
	}
	if (will_wire_function_panic_due_to_vm_tag(start)) {
		return BUSTED;
	}


	ppnum_t physpage;
	kern_return_t kr = vm_map_wire_external(map, start, end, prot, TRUE);
	return kr;
}

static kern_return_t
call_vm_map_wire_external_vm_prot_t_non_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_prot_t prot)
{
	mach_vm_address_t end;
	if (__builtin_add_overflow(start, size, &end)) {
		return BUSTED;
	}
	if (will_wire_function_panic_due_to_alignment(start, end)) {
		return PANIC;
	}
	if (will_wire_function_panic_due_to_vm_tag(start)) {
		return BUSTED;
	}


	ppnum_t physpage;
	kern_return_t kr = vm_map_wire_external(map, start, end, prot, FALSE);
	if (kr == KERN_SUCCESS) {
		(void) vm_map_unwire(map, start, end, FALSE);
	}
	return kr;
}

static kern_return_t
call_vm_map_wire_kernel_vm_prot_t_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_prot_t prot)
{
	mach_vm_address_t end;
	if (__builtin_add_overflow(start, size, &end)) {
		return BUSTED;
	}
	if (will_wire_function_panic_due_to_alignment(start, end)) {
		return PANIC;
	}

	ppnum_t physpage;
	kern_return_t kr = vm_map_wire_kernel(map, start, end, prot, VM_KERN_MEMORY_OSFMK, TRUE);
	return kr;
}

static kern_return_t
call_vm_map_wire_kernel_vm_prot_t_non_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_size_t size, vm_prot_t prot)
{
	mach_vm_address_t end;
	if (__builtin_add_overflow(start, size, &end)) {
		return BUSTED;
	}
	if (will_wire_function_panic_due_to_alignment(start, end)) {
		return PANIC;
	}

	ppnum_t physpage;
	kern_return_t kr = vm_map_wire_kernel(map, start, end, prot, VM_KERN_MEMORY_OSFMK, FALSE);
	if (kr == KERN_SUCCESS) {
		(void) vm_map_unwire(map, start, end, FALSE);
	}
	return kr;
}


static kern_return_t
call_vm_map_kernel_tag_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_address_t end, vm_tag_t tag)
{
	if (will_wire_function_panic_due_to_alignment(start, end)) {
		return PANIC;
	}
	if (tag == VM_KERN_MEMORY_NONE) {
		return PANIC;
	}
	kern_return_t kr = vm_map_wire_kernel(map, start, end, VM_PROT_DEFAULT, tag, TRUE);
	if (kr == KERN_SUCCESS) {
		(void) vm_map_unwire(map, start, end, TRUE);
	}
	return kr;
}

static kern_return_t
call_vm_map_kernel_tag_non_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_address_t end, vm_tag_t tag)
{
	if (will_wire_function_panic_due_to_alignment(start, end)) {
		return PANIC;
	}
	if (tag == VM_KERN_MEMORY_NONE) {
		return PANIC;
	}
	kern_return_t kr = vm_map_wire_kernel(map, start, end, VM_PROT_DEFAULT, tag, FALSE);
	if (kr == KERN_SUCCESS) {
		(void) vm_map_unwire(map, start, end, FALSE);
	}
	return kr;
}


static kern_return_t
call_mach_vm_wire_level_monitor(int64_t requested_pages)
{
	kern_return_t kr = mach_vm_wire_level_monitor(requested_pages);
	return kr;
}

static kern_return_t
call_vm_map_unwire_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_address_t end)
{
	if (will_wire_function_panic_due_to_alignment(start, end)) {
		return PANIC;
	}

	kern_return_t kr = vm_map_unwire(map, start, end, TRUE);
	return kr;
}


static kern_return_t
call_vm_map_unwire_non_user_wired(MAP_T map, mach_vm_address_t start, mach_vm_address_t end)
{
	if (will_wire_function_panic_due_to_alignment(start, end)) {
		return PANIC;
	}

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
call_vm_map_copyout(MAP_T dst_map, vm_map_copy_t copy)
{
	// save this value because `copy` is destroyed by vm_map_copyout_size()
	mach_vm_size_t copy_size = copy ? copy->size : 0;
	vm_map_address_t dst_addr;
	kern_return_t kr = vm_map_copyout(dst_map, &dst_addr, copy);
	if (kr == KERN_SUCCESS) {
		if (copy != NULL) {
			(void) mach_vm_deallocate(dst_map, dst_addr, copy_size);
		}
	}
	return kr;
}

static kern_return_t
call_vm_map_copyout_size(MAP_T dst_map, vm_map_copy_t copy, mach_vm_size_t size)
{
	// save this value because `copy` is destroyed by vm_map_copyout_size()
	mach_vm_size_t copy_size = copy ? copy->size : 0;
	vm_map_address_t dst_addr;
	kern_return_t kr = vm_map_copyout_size(dst_map, &dst_addr, copy, size);
	if (kr == KERN_SUCCESS) {
		if (copy != NULL) {
			(void) mach_vm_deallocate(dst_map, dst_addr, copy_size);
		}
	}
	return kr;
}

static kern_return_t
call_vm_map_copy_overwrite_interruptible(MAP_T dst_map, vm_map_copy_t copy, mach_vm_address_t dst_addr, mach_vm_size_t copy_size)
{
	kern_return_t kr = vm_map_copy_overwrite(dst_map, dst_addr, copy, copy_size, TRUE);
	return kr;
}

static kern_return_t
call_vm_map_copy_overwrite_non_interruptible(MAP_T dst_map, vm_map_copy_t copy, mach_vm_address_t dst_addr, mach_vm_size_t copy_size)
{
	kern_return_t kr = vm_map_copy_overwrite(dst_map, dst_addr, copy, copy_size, FALSE);
	return kr;
}

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
		if (map_size != invalid_initial_size) {
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
	 * INVALID_INITIAL_SIZE is guaranteed to never be the correct map_size
	 * from the mach_memory_entry_map_size calls we make. map_size should represent the size of the
	 * copy that would result, and INVALID_INITIAL_SIZE is completely unrelated to the sizes we pass
	 * and not page aligned.
	 */
	mach_vm_size_t invalid_initial_size = INVALID_INITIAL_SIZE;

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

static inline void
check_mach_memory_entry_outparam_changes(kern_return_t * kr, mach_vm_size_t size,
    mach_port_t out_handle, mach_port_t saved_handle)
{
	/*
	 * mach_make_memory_entry overwrites *size to be 0 on failure.
	 */
	if (*kr != KERN_SUCCESS) {
		if (size != 0) {
			*kr = OUT_PARAM_BAD;
		}
		if (out_handle != saved_handle) {
			*kr = OUT_PARAM_BAD;
		}
	}
}
// mach_make_memory_entry and variants

#define IMPL(FN, T)                                                               \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__memonly(MAP_T map, T start, T size)                      \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_handle_value = INVALID_INITIAL_MACH_PORT;     \
	        mach_port_t out_handle = invalid_handle_value;                    \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_ONLY, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                if (out_handle) mach_memory_entry_port_release(out_handle); \
	        }                                                                 \
	        mach_memory_entry_port_release(memobject);                        \
	        check_mach_memory_entry_outparam_changes(&kr, io_size, out_handle,\
	                                                 invalid_handle_value);   \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__namedcreate(MAP_T map, T start, T size)                  \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_handle_value = INVALID_INITIAL_MACH_PORT;     \
	        mach_port_t out_handle = invalid_handle_value;                    \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_NAMED_CREATE, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                if (out_handle) mach_memory_entry_port_release(out_handle); \
	        }                                                                 \
	        mach_memory_entry_port_release(memobject);                        \
	        check_mach_memory_entry_outparam_changes(&kr, io_size, out_handle,\
	                                                 invalid_handle_value);   \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__copy(MAP_T map, T start, T size)                         \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_handle_value = INVALID_INITIAL_MACH_PORT;     \
	        mach_port_t out_handle = invalid_handle_value;                    \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_VM_COPY, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                if (out_handle) mach_memory_entry_port_release(out_handle); \
	        }                                                                 \
	        mach_memory_entry_port_release(memobject);                        \
	        check_mach_memory_entry_outparam_changes(&kr, io_size, out_handle,\
	                                                 invalid_handle_value);   \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__share(MAP_T map, T start, T size)            \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_handle_value = INVALID_INITIAL_MACH_PORT;     \
	        mach_port_t out_handle = invalid_handle_value;                    \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_VM_SHARE, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                if (out_handle) mach_memory_entry_port_release(out_handle); \
	        }                                                                 \
	        mach_memory_entry_port_release(memobject);                        \
	        check_mach_memory_entry_outparam_changes(&kr, io_size, out_handle,\
	                                                 invalid_handle_value);   \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __start_size__namedreuse(MAP_T map, T start, T size)       \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_handle_value = INVALID_INITIAL_MACH_PORT;     \
	        mach_port_t out_handle = invalid_handle_value;                    \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              VM_PROT_READ | MAP_MEM_NAMED_REUSE, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                if (out_handle) mach_memory_entry_port_release(out_handle); \
	        }                                                                 \
	        mach_memory_entry_port_release(memobject);                        \
	        check_mach_memory_entry_outparam_changes(&kr, io_size, out_handle,\
	                                                 invalid_handle_value);   \
	        return kr;                                                        \
	}                                                                         \
                                                                                  \
	static kern_return_t                                                      \
	call_ ## FN ## __vm_prot(MAP_T map, T start, T size, vm_prot_t prot)      \
	{                                                                         \
	        mach_port_t memobject = make_a_mem_object(TEST_ALLOC_SIZE + 1);          \
	        T io_size = size;                                                 \
	        mach_port_t invalid_handle_value = INVALID_INITIAL_MACH_PORT;     \
	        mach_port_t out_handle = invalid_handle_value;                    \
	        kern_return_t kr = FN(map, &io_size, start,                       \
	                              prot, &out_handle, memobject); \
	        if (kr == 0) {                                                    \
	                if (out_handle) mach_memory_entry_port_release(out_handle); \
	        }                                                                 \
	        mach_memory_entry_port_release(memobject);                        \
	        check_mach_memory_entry_outparam_changes(&kr, io_size, out_handle,\
	                                                 invalid_handle_value);   \
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

static bool
dealloc_would_panic(mach_vm_address_t start, mach_vm_size_t size)
{
	return (start > 0xffffffffffffbffd) ||
	       (size > 0x8000000000);
}

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
	if (dealloc_would_panic(*address, size)) {
		return PANIC;
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
	if (dealloc_would_panic(*address, size)) {
		return PANIC;
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
	if (dealloc_would_panic(*address, size)) {
		return PANIC;
	}
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;

	vm_map_kernel_flags_set_vmflags(&vmk_flags, flags);
	mach_vm_address_t saved_addr = *address;
	kern_return_t kr = mach_vm_map_kernel(target_task, address, size, mask, vmk_flags, object, offset, copy, cur_protection, max_protection, inheritance);
	check_mach_vm_map_outparam_changes(&kr, *address, saved_addr, flags, target_task);
	return kr;
}

struct file_control_return {
	void * control;
	void * fp;
	void * vp;
	int fd;
};

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

struct file_control_return get_control_from_fd(int fd);
void cleanup_control_related_data(struct file_control_return info);
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
	mach_vm_address_t start = vm_map_trunc_page(*address, VM_MAP_PAGE_MASK(target_map));
	mach_vm_address_t end = round_up_page(*address + size, PAGE_SIZE);
	mach_vm_address_t end_offset;
	if (__builtin_add_overflow(end - start, offset, &end_offset)) {
		return PANIC;
	}

	vm_map_offset_t         vmmaddr;
	vmmaddr = (vm_map_offset_t) *address;

	if (dealloc_would_panic(*address, size)) {
		return PANIC;
	}
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
	if (dealloc_would_panic(*address, size)) {
		return PANIC;
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
	if (dealloc_would_panic(*address, size)) {
		return PANIC;
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
	} else {
		init_kernel_generate_golden();
	}

	/*
	 * Group 1: memory entry
	 */

#define RUN_START_SIZE(fn, variant, name) dealloc_results(dump_results(test_mach_with_allocated_start_size(call_ ## fn ## __start_size__ ## variant, name " (start/size)")))
#define RUN_PROT(fn, name) dealloc_results(dump_results(test_mach_with_allocated_vm_prot_t(call_ ## fn ## __vm_prot , name " (vm_prot_t)")))

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

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_ledger_tag(fn, name " (ledger tag)")))
	RUN(call_mach_memory_entry_ownership__ledger_tag, "mach_memory_entry_ownership");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_ledger_flag(fn, name " (ledger flag)")))
	RUN(call_mach_memory_entry_ownership__ledger_flag, "mach_memory_entry_ownership");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_mach_memory_entry_map_size__start_size, "mach_memory_entry_map_size");
#undef RUN

	/*
	 * Group 2: allocate/deallocate
	 */

#define RUN(fn, name) dealloc_results(dump_results(test_mach_allocation_func_with_start_size(fn, name)))
	RUN(call_mach_vm_allocate__start_size_fixed, "mach_vm_allocate_external (fixed) (realigned start/size)");
	RUN(call_mach_vm_allocate__start_size_anywhere, "mach_vm_allocate_external (anywhere) (hint/size)");
	RUN(call_mach_vm_allocate_kernel__start_size_fixed, "mach_vm_allocate (fixed) (realigned start/size)");
	RUN(call_mach_vm_allocate_kernel__start_size_anywhere, "mach_vm_allocate (anywhere) (hint/size)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_allocation_func_with_vm_map_kernel_flags_t(fn, name " (vm_map_kernel_flags_t)")))
	RUN(call_mach_vm_allocate__flags, "mach_vm_allocate_external");
	RUN(call_mach_vm_allocate_kernel__flags, "mach_vm_allocate_kernel");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_allocation_func_with_start_size(fn, name)))
	RUN(call_vm_allocate__start_size_fixed, "vm_allocate (fixed) (realigned start/size)");
	RUN(call_vm_allocate__start_size_anywhere, "vm_allocate (anywhere) (hint/size)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_allocation_func_with_vm_map_kernel_flags_t(fn, name " (vm_map_kernel_flags_t)")))
	RUN(call_vm_allocate__flags, "vm_allocate");
#undef RUN
	dealloc_results(dump_results(test_deallocator(call_mach_vm_deallocate, "mach_vm_deallocate (start/size)")));
	dealloc_results(dump_results(test_deallocator(call_vm_deallocate, "vm_deallocate (start/size)")));

	/*
	 * Group 3: map/remap
	 */

	// map tests

#define RUN_START_SIZE(fn, name) dealloc_results(dump_results(test_mach_with_allocated_start_size(fn, name " (realigned start/size)")))
#define RUN_HINT_SIZE(fn, name) dealloc_results(dump_results(test_mach_with_allocated_start_size(fn, name " (hint/size)")))
#define RUN_PROT_PAIR(fn, name) dealloc_results(dump_results(test_mach_vm_prot_pair(fn, name " (vm_prot_t pair)")))
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
	RUN_ALL(mach_vm_map_external_wrapped, mach_vm_map_external);
	RUN_ALL(mach_vm_map_kernel_wrapped, mach_vm_map_kernel);
	RUN_ALL(vm_map_wrapped, vm_map);
	RUN_ALL(vm_map_external_wrapped, vm_map_external);

#define RUN_SSO(fn, name) dealloc_results(dump_results(test_mach_with_start_size_offset(fn, name " (start/size/offset)")))

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
#define RUN_HELPER(harness, fn, variant, type, type_name, name) dealloc_results(dump_results(harness(FN_NAME(fn, variant, type), #name " (" #variant ") (" type_name ")")))
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
	 * Group 4: wire/unwire
	 */

#define RUN(fn, name) dealloc_results(dump_results(test_kext_unix_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_vslock, "vslock");
	RUN(call_vsunlock_undirtied, "vsunlock (undirtied)");
	RUN(call_vsunlock_dirtied, "vsunlock (dirtied)");
#undef RUN

#if XNU_PLATFORM_MacOSX
	// vm_map_wire_and_extract is implemented on macOS only
#define RUN(fn, name) dealloc_results(dump_results(test_kext_tagged_with_allocated_addr(fn, name " (addr)")))
	RUN(call_vm_map_wire_and_extract_user_wired, "vm_map_wire_and_extract (user wired)");
	RUN(call_vm_map_wire_and_extract_non_user_wired, "vm_map_wire_and_extract (user wired)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
	RUN(call_vm_map_wire_and_extract_vm_prot_t_user_wired, "vm_map_wire_and_extract_external (user wired)");
	RUN(call_vm_map_wire_and_extract_vm_prot_t_non_user_wired, "vm_map_wire_and_extract_external (non user wired)");
#undef RUN
#endif // XNU_PLATFORM_MacOSX

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_allocated_vm_prot_t(fn, name " (vm_prot_t)")))
	RUN(call_vm_map_wire_external_vm_prot_t_user_wired, "vm_map_wire_external (user wired)");
	RUN(call_vm_map_wire_external_vm_prot_t_non_user_wired, "vm_map_wire_external (non user wired))");
	RUN(call_vm_map_wire_kernel_vm_prot_t_user_wired, "vm_map_wire_kernel (user wired)");
	RUN(call_vm_map_wire_kernel_vm_prot_t_non_user_wired, "vm_map_wire_kernel (non user wired))");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_with_start_end(fn, name " (start/end)")))
	RUN(call_vm_map_wire_external_user_wired, "vm_map_wire_external (user wired)");
	RUN(call_vm_map_wire_external_non_user_wired, "vm_map_wire_external (non user wired)");
	RUN(call_vm_map_wire_kernel_user_wired, "vm_map_wire_kernel (user wired)");
	RUN(call_vm_map_wire_kernel_non_user_wired, "vm_map_wire_kernel (non user wired)");
	RUN(call_vm_map_unwire_user_wired, "vm_map_unwire (user_wired)");
	RUN(call_vm_map_unwire_non_user_wired, "vm_map_unwire (non user_wired)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_with_tag(fn, name " (tag)")))
	RUN(call_vm_map_kernel_tag_user_wired, "vm_map_wire_kernel (user wired)");
	RUN(call_vm_map_kernel_tag_non_user_wired, "vm_map_wire_kernel (non user wired)");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_with_int64(fn, name " (int64)")))
	RUN(call_mach_vm_wire_level_monitor, "mach_vm_wire_level_monitor");
#undef RUN

	/*
	 * Group 5: copyin/copyout
	 */

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_allocated_start_size(fn, name " (start/size)")))
	RUN(call_vm_map_copyin, "vm_map_copyin");
	// vm_map_copyin_common is covered well by the vm_map_copyin test
	// RUN(call_vm_map_copyin_common, "vm_map_copyin_common");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_mach_with_allocated_addr_of_size_n(fn, sizeof(uint32_t), name " (start)")))
	RUN(call_copyoutmap_atomic32, "copyoutmap_atomic32");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_src_kerneldst_size(fn, name " (src/dst/size)")))
	RUN(call_copyinmap, "copyinmap");
	RUN(call_vm_map_read_user, "vm_map_read_user");
#undef RUN

#define RUN(fn, name) dealloc_results(dump_results(test_kernelsrc_dst_size(fn, name " (src/dst/size)")))
	RUN(call_vm_map_write_user, "vm_map_write_user");
	RUN(call_copyoutmap, "copyoutmap");
#undef RUN

	dealloc_results(dump_results(test_vm_map_copy_overwrite(call_vm_map_copy_overwrite_interruptible, "vm_map_copy_overwrite (start/size)")));

	SYSCTL_OUTPUT_BUF = 0;
	SYSCTL_OUTPUT_END = 0;
	*out_value = 1;  // success
	return 0;
}

SYSCTL_TEST_REGISTER(vm_parameter_validation_kern, vm_parameter_validation_kern_test);
