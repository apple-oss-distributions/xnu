# VM API parameter sanitization

Validating parameter values passed to virtual memory APIs primarily from user
space.

## Overview

VM parameter sanitization aims to eliminate shallow input validation
bugs like overflows caused by rounding addresses to required page size,
by providing a set of APIs that can be used to perform consistent, thorough
mathematical checks on the input. This allows for the rest of the subsystem to
freely operate on the input without worrying that future computations may
overflow. Note that these APIs are meant to primarily catch issues with
mathematical computation and are not responsible for checking if the input
value is within certain expected bounds or valid in the context of a specific
VM API.

## Semantic types

To enforce that sanitization is performed on input prior to use,
unsafe input types are encapsulated as opaque types (i.e wrapped inside a
transparent union) to the internal implementation of the VM APIs. Performing
mathematical operations on these opaque values without calling the
respective sanitization functions (that validates and unwraps them)
will generate a compiler error.

Types that are typically considered unsafe (i.e require sanitization) include:
- Address/offset for example vm_offset_t and vm_address_t
- Size for example vm_size_t
- Various flags like vm_prot_t and vm_inherit_t

## Sanitizer functions

The functions that sanitize various types of input values are implemented
in `vm_sanitize.c` and documented in their corresponding header
`vm_sanitize_internal.h`.

## VM API boundary

VM functions can be called from three places: userspace, kexts, and xnu itself.
Functions callable from userspace should be fully sanitized. Functions
callable from kexts and xnu are less thoroughly covered today.

## Telemetry and error code compatibility

When VM parameter sanitization finds a problem, it does the following:
- returns an error to the API's caller
- optionally *rewrites* that error first, either to a different
  error code or to `KERN_SUCCESS`.
- optionally *telemeters* that error, sending it to CoreAnalytics and ktriage.

The option to rewrite and/or telemeter is chosen based on the sanitizer
type and on the identity of the VM API that called the sanitizer.
The VM API identity is the `vm_sanitize_caller_t` passed to the sanitizer
function. This identity contains function pointers that override the
default behavior (i.e. no rewrite, no telemetry). The overrides, if any, are set
by `VM_SANITIZE_DEFINE_CALLER` in `vm_sanitize_error_compat.c`.

Error code rewrites change the error code to better match historical
behavior for binary compatibility purposes. There are two possible rewrites:
1. rewrite an error code to be a different error code.
2. rewrite an error code to be `KERN_SUCCESS`. The VM API returns success
   immediately without executing the rest of its implementation.
Not all changed error codes are (or could be) rewritten.

Telemetry similarly may record two cases:
1. The error code being returned differs from its historical value.
2. The error code being returned would be different from its historical
   value, but a rewrite has changed it to match the historical value instead.
Not all changed error codes are (or could be) telemetered. Currently all
rewrites performed are telemetered.

An outline of the sequence:
1. VM API calls a sanitizer function, passing its own identity in `vms_caller`.
2. `vm_sanitize_<kind>` looks for invalid parameters.
3. If an invalid parameter is found, the sanitizer calls
   `vm_sanitize_err_compat_<kind>` to handle any rewrites or telemetry.
4. `vm_sanitize_err_compat_<kind>` looks for an override handler
   for that type in the caller's identity, and calls it if present.
5. `vm_sanitize_err_compat_<kind>_<caller>`, the override handler, examines the
   parameters and chooses whether to rewrite and/or telemeter this error.
   It returns a `vm_sanitize_compat_rewrite_t` containing its decision.
6. `vm_sanitize_err_compat_<kind>` applies any requested error code rewrite
   and sends any requested telemetry.
7. The VM API receives the error from the sanitizer and returns it.

There is a complication in step #7: how do the error compat and
the sanitizer tell the VM API that it should halt and return `KERN_SUCCESS`
immediately, distinct from the sanitizer telling the VM API that
sanitization succeeded and the VM API should proceed normally?
The scheme looks like this:
- sanitizer returns `KERN_SUCCESS`: VM API may proceed normally
- sanitizer returns not-`KERN_SUCCESS`: VM API shall return immediately
  - sanitizer returns `VM_ERR_RETURN_NOW`: VM API shall return `KERN_SUCCESS` now
  - sanitizer returns any other error code: VM API shall return that error now
The mapping of `VM_ERR_RETURN_NOW` to `KERN_SUCCESS` is performed by
`vm_sanitize_get_kern_return`.

## How to: add a new sanitizer or sanitized type

When a new type needs sanitization, use one of the following macros to declare
and define the encapsulated opaque version:
- `VM_GENERATE_UNSAFE_ADDR`: Should be used for a new variant that represents
  address or offset
- `VM_GENERATE_UNSAFE_SIZE`: Should be used for a new variant that represents
  size
- `VM_GENERATE_UNSAFE_TYPE`: Should be used for other types that are not
  address or size. For example, this macro is currently used to define the
  opaque protections type `vm_prot_ut`.

These opaque types are declared in `vm_types_unsafe.h`. There are also some
variants of these macros for specific purposes:
- 32 bit variants like `VM_GENERATE_UNSAFE_ADDR32` should be used for 32bit
  variants of address, offset and size.
- BSD variants like `VM_GENERATE_UNSAFE_BSD_ADDR` for types that are
  specifically used in the BSD subsystem and not in mach (for example:
  caddr_t).
- EXT variants like `VM_GENERATE_UNSAFE_EXT` should not be used directly. They
  are intermediate implementation macros.
- `VM_GENERATE_UNSAFE_WRAPPER` is a special macro that is needed to avoid
  compiler errors when pointers of opaque types of a specific kind are
  interchangeably used as pointer of another opaque type of the same kind for
  example:
  ```
  mach_vm_offset_ut *offset;
  ...
  mach_vm_address_ut *ptr = offset;
  ```
  These macros define a common opaque type for the entire kind that other
  `_ADDR`/`_SIZE` macros redirect to.
  ```
  VM_GENERATE_UNSAFE_WRAPPER(uint64_t, vm_addr_struct_t);
  ```
  generates the common opaque type for address and offset. All the `_ADDR`
  macros define respective opaque types as a typedef of
  `vm_addr_struct_t`.
  ```
  VM_GENERATE_UNSAFE_ADDR(mach_vm_address_t, mach_vm_address_ut);
  ```
  typedefs `mach_vm_address_ut` as a `vm_addr_struct_t`.

## How to: add sanitization to new VM API

Once the opaque type is available to use, modify the respective
declaration/definition of the entry point to use the opaque types.

### Opaque types in function prototype

#### Adoption in MIG

For APIs that are exposed via MIG, adopting the new opaque type in the
API requires some additional steps as we want the opaque types to only appear
in the kernel headers, leaving the userspace headers unchanged.
- Associate the safe type with its unsafe type using `VM_UNSAFE_TYPE` or
  `VM_TYPE_SAFE_UNSAFE` macros. For example:
  ```
  type mach_vm_address_t = uint64_t VM_UNSAFE_TYPE(mach_vm_address_ut);
  ```
  will cause MIG to use the original type `mach_vm_address_t` in the userspace
  headers that are generated by MIG, but overload with the unsafe type
  `mach_vm_address_ut` for kernel headers.
  Similarly,
  ```
  type pointer_t = ^array[] of MACH_MSG_TYPE_BYTE
	VM_TYPE_SAFE_UNSAFE(vm_offset_t, pointer_ut);
  ```
  replaces `pointer_t` with `vm_offset_t` in userspace headers
  and `pointer_ut` in kernel headers.
- Ensure that `VM_KERNEL_SERVER` is defined at the top of the defs file before
  any includes.
- Adopt the opaque types in the function definition present in the `.c` file.
  ```
  kern_return_t
  mach_vm_read(
    	vm_map_t                map,
    	mach_vm_address_ut      addr,
    	mach_vm_size_ut         size,
    	pointer_ut             *data_u,
    	mach_msg_type_number_t *data_size)
  ```

#### Adoption in syscalls

- Ensure that you have created the opaque types needed by the BSD subsystem
  using `VM_GENERATE_UNSAFE_BSD_*` in `osfmk/mach/vm_types_unsafe.h`.
- Add the new opaque type to `sys/_types/*` or `bsd/<arm or i386>/types.h`.
  `caddr_ut` was added to `bsd/sys/_types/_caddr_t.h` and `user_addr_ut` was
  added to `bsd/arm/types.h` and `bsd/i386/types.h`. When adding an opaque for
  `caddr_t` you may also need to add opaque types for corresponding types like
  `user_addr_t` as the syscall generated use those types.
- Also add the types to `libsyscall/xcodescripts/create-syscalls.pl`.
- Adopt the opaque type in the API in `syscalls.master`.
  ```
  203	AUE_MLOCK	ALL	{ int mlock(caddr_ut addr, size_ut len); }
  ```
  `mlock` uses opaque type `caddr_ut` for its address and `size_ut` for its
  size.
- Modify `bsd/kern/makesyscalls.sh` to handle the new types added.

#### Adoption in mach traps

Function prototypes aren't generated automatically for mach traps as is the
case for syscalls. Therefore we need to modify the mach trap manually to use
the opaque type in `osfmk/mach/mach_traps.h`.
```
struct _kernelrpc_mach_vm_deallocate_args {
	PAD_ARG_(mach_port_name_t, target);     /* 1 word */
	PAD_ARG_(mach_vm_address_ut, address);  /* 2 words */
	PAD_ARG_(mach_vm_size_ut, size);        /* 2 words */
};                                              /* Total: 5 */
extern kern_return_t _kernelrpc_mach_vm_deallocate_trap(
	struct _kernelrpc_mach_vm_deallocate_args *args);
```
### Perform sanitization

Now that the internal function definitions see the opaque types, we need to
perform the required sanitization. If multiple entry points call the same
internal function, pass along the unsafe value and perform the check at the
best choke point further down. For example the best choke point for the
following APIs was `vm_map_copyin_internal`:
- `mach_vm_read`
- `vm_read`
- `mach_vm_read_list`
- `vm_read_list`
- `vm_map_copyin`
- `mach_vm_read_overwrite`
- `mach_vm_copy`

Once you have determined the right choke point create a
`<function name>_sanitize` function that will sanitize all opaque types and
return their unwrapped safe values. In this function you should call the
sanitization functions provided in `vm_sanitize.c` to validate all opaque
types adopted by the API. If you added a new type that doesn't have a
corresponding sanitization function in `vm_sanitize.c`, please add one.
For existing types, try to reuse the functions provided instead of
writing new ones with specific purposes. `vm_sanitize.c` is meant to
contain the basic blocks that could be chained to meet your specific
requirements.

#### Adding new functions to `vm_sanitize.c`

- Mark function with `__attribute__((always_inline,
  warn_unused_result))`.
- Ensure that you return safe values on failure for all opaque types that
  were supposed to be sanitized by the function.

### Enforcement

For files outside `osfmk/vm` and `bsd/vm` that need to see the opaque type
add the following to their `conf/Makefile.template`:
```
kern_mman.o_CFLAGS_ADD += -DVM_UNSAFE_TYPES
```

## Tests

Most VM API callable from userspace or kexts have tests that pass correct and
incorrect input values, to verify that the functions return the expected error
codes. These tests run every VM function that has sanitized parameters dozens
or hundreds or thousands of times.

The code for these tests is:
- `tests/vm/vm_parameter_validation.c` (test `vm_parameter_validation_user`
for userspace call sites)
- `osfmk/tests/vm_parameter_validation_kern.c` (test
`vm_parameter_validation_kern` for kernel or kext call sites)

The expected error codes returned by these calls are stored in "golden" result
files. If you change the error code of a VM API, or define a new flag bit that
was previously unused, you may need to update the golden results.
See `tests/vm/vm_parameter_validation.c` for instructions.

You can run these tests locally. See `tests/vm/vm_parameter_validation.c`
for instructions.

A *trial* is a single VM function called with a single set of argument values.
For example, `mach_vm_protect(VM_PROT_READ)` with address=0 and size=0 is a
single trial.

A *test* is made up of multiple trials: a single VM function called many
times with many values for one sanitized parameter (or group of related
parameters). For example, `mach_vm_protect(VM_PROT_READ)` with many different
pairs of address and size is a single test. `mach_vm_protect` with a single
valid address+size and many different `vm_prot_t` values is another test.

The trial values in these tests are generally intended to provoke bugs
that the sanitizers are supposed to catch. The list of trial values for
address+size provokes various integer overflows if they are added and/or
rounded. The list of trial values for flags like `vm_prot_t` includes at
least one trial for every possible set bit. The list of trial values for
a sanitized type or group of types is produced by a "generator". Each
trial generator is in `osfmk/tests/vm_parameter_validation.h`.

A test `harness` or `runner` is the loop that runs a VM function with
every trial value, performing any setup necessary and collecting the results.
These function names start with `test_`. For example,
`test_mach_with_allocated_vm_prot_t` runs `vm_prot_t` trials of a VM API,
each time passing it the address and size of a valid allocation and a
different `vm_prot_t` value. This particular runner is used by some tests of
`mach_vm_protect`, `mach_vm_wire`, and others.

The output of all trials in one test is collected as `results_t`, storing the
name of the test, the name of each trial, and the error code from each trial.
The "error code" is also used for trial outcomes that are not return values
from the VM API. For example, value `PANIC` means the trial was deliberately
not executed because if it were it would have panicked and the test machinery
can't handle that.

After each test the collected results are processed. Normally this means
comparing them to the expected results from the golden files. Test results
may also be used to generate new golden files. Test results may also be
dumped to console in their entirety. You can pipe dumped output to
`tools/format_vm_parameter_validation.py`, which knows how to pretty-print
some things.

These tests are intended to exercise every kernel entry point from userspace 
directly, both MIG and syscall, even for functions that have no access via 
Libsystem or that Libsystem intercepts. For MIG entry points we generate our 
own MIG call sites; see `tests/Makefile` for details. For syscall entry points
we sometimes call a `__function_name` entry point exported by Libsystem that
is more direct than `function_name` would be. Examples: `__mmap`, `__msync`,
`__msync_nocancel`.

There are two sets of kernel entrypoints that are not exercised by these tests
today:
1. the MIG entrypoints that use 32-bit addresses, on platforms other than
watchOS. These kernels respond to these MIG messages but Libsystem never sends
them. We reviewed the vm32 implementations and decided they were safe and
unlikely to do unsanitary things with the input values before passing them
to VM API that perform sanitizations. These entrypoints should be disabled
(rdar://124030574).
2. the `kernelrpc` trap alternatives to some MIG entrypoints. We reviewed
the trap implementations and decided they were safe and unlikely to do
unsanitary things with the input values before passing them to VM API that
perform sanitizations.

## How to: add a new test

You may need to write new tests in `vm_parameter_validation` if you do 
one of the following:
- write a new VM API function (for userspace or kexts) that has parameters of 
sanitized types
- implement sanitization in an existing VM API function for a parameter that
was not previously sanitized

Step 1: are you testing userspace callers (`tests/vm/vm_parameter_validation.c`),
kernel/kext callers (`osfmk/tests/vm_parameter_validation_kern.c`), or both?
If you are testing both kernel and userspace you may be able to share much of
the implementation in the common file `osfmk/tests/vm_parameter_validation.h`.

Step 2: decide what functions you are testing. Each API function with sanitized
parameters get at least one test. Some functions are divided into multiple
independent tests because the function has multiple modes of operation that
use different parameter validation paths internally. For example,
`mach_vm_allocate(VM_FLAGS_FIXED)` and `mach_vm_allocate(VM_FLAGS_ANYWHERE)`
each get their own set of tests as if they were two different functions,
because each handles their `addr/size` parameters differently.

Step 3: decide what parameters you are testing. Each sanitized parameter or
group of related parameters gets its own test. For example, `mach_vm_protect`
has two parameter tests to perform, one for the protection parameter and one
for the address and size parameters together. The sanitization of address and
size are intertwined (we check for overflow of address+size), so they are
tested together. The sanitization of the protection parameter is independent
of the address and size, so it is tested separately.

Step 4: for each parameter or group of parameters, decide what trial values
should be tested. The trials should be exhaustive for small values, and
exercise edge cases and invalid state for large values and interconnected
values. `vm_prot_t` is exhaustive at the bit level (each bit is set in at
least one trial) and probes edge cases like `rwx`. Address and size trials
probe for overflows when the values are added and/or rounded to page sizes.
Choose existing trial value generators for your parameters, or write new
generators if you want a new type or different values for an existing type.
Note that the trial name strings produced by the generator are used by
`tools/format_vm_parameter_validation.py` to pretty-print your output;
you may even want to edit that script to recognize new things from your
code. The trial names are also used in the golden files; each trial
name must be unique within a single test.

Step 5: for each test, decide what setup is necessary for the test or for
each trial in the test. Choose an existing test running or write a new
runner with that setup and those trials. The test runner loops through
the trial values produced by the trial generators above, performs the
required setup for the test or for each trial, and calls the function
to be tested. If there is an existing VM API with similar setup or
similar parameters to yours then you can use the same runner or implement
a variation on that runner.

Step 6: if your VM API function has out parameters, test that they are
modified or not modified as expected. This is not strictly related to
parameter sanitization, but the sanitization error paths often have
inconsistent out parameter handling so these tests are a convenient
place to verify the desired behavior.

Step 7: call all of your new tests from the top-level test functions
`vm_parameter_validation_kern_test` and `vm_parameter_validation_user`.
Wrap your calls in the same processing and deallocation functions as the
other tests. You should not need to modify either of them. Note that string
used to label the test (with the function and parameters being tested) is
used by the pretty-printing in `tools/format_vm_parameter_validation.py`
so choose it wisely; you may even want to edit that script to recognize
new things from your code. The test name is also recorded in the golden
files; each test name must be unique.

Step 8: run your new tests and verify that the patterns of success and
error are what you want. `tools/format_vm_parameter_validation.py` can
pretty-print some of these outputs which makes them easier to examine.
Make sure you test the platforms with unusual behavior, such as Intel
and Rosetta where page sizes are different. See
`tests/vm/vm_parameter_validation.c` for instructions on how to run your
tests in BATS or locally.

Step 9: if you are adding sanitization to an existing VM API, decide if
you need error code compatibility handling. Run your new test before and
after your new sanitization code is in place and compare the output from
`DUMP_RESULTS=1`. If your new sanitization has changed the function's
error code behavior then you may want to write error code compatibility
rewrites and/or telemetry for binary compatibility.

Step 10: update the "golden" files of expected results. This is done last
when you are confident that your sanitization and tests are complete and
stable. See `tests/vm/vm_parameter_validation.c` for instructions.
