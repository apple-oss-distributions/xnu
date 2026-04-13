# XNU user-space unit-tests

This folder contains unit-tests for in-kernel functionality, built to run as a user-space process.

## Building a test:
```
> make -C tests/unit SDKROOT=macosx.internal <test-name>
```
This will build XNU as a library and link it into a test executable.  
`<test-name>` is the name of the test executable. There should be a corresponding `<test-name>.c`
Examples for `<test-name>`: `example_test_osfmk`, `example_test_bsd`

Useful customization for the make command:
- `VERBOSE=YES`  - Show more of the build commands
- `BUILD_WERROR=0`  - When building XNU, Do not treat warnings to errors
- `SKIP_XNU=1`  - Don't try to rebuild XNU
- `NO_LLDBMACROS=1`  - Don't copy the lldbmacros into the kernel dylib. This can save some time when debugging
- `BUILD_CODE_COVERAGE=1`  - Build with coverage support, see section below
- `KERNEL_CONFIG=release`  - Build XNU in release rather than 'development'
- `PRODUCT_CONFIG=...`  - Build XNU for a device other than the default. 
    - macOS, and iOS devices are supported.
    - device must be SPTM enabled.
    - `SDKROOT` must still be set to `macosx.internal` even when building XNU for a non-macos product.
      This is because the executable is meant for running on macOS.
    - The `BUILD` and `tests/unit/build` folders may need to be deleted when changing device since
      the XNU makefile do not fully detect the needed changes.
    - The ARM version (-mcpu) of the machine which runs the test must be equal or better than that of the 
      given target product, Otherwise it will not be able to run the emitted instructions.
- `FIBERS_PREEMPTION=1`  - Build with memory operations instrumentation to simulate preemption, see section below
- `BUILD_ASAN=1`  - Build with AddressSanitizer support
- `BUILD_UBSAN=1`  - Build with UndefinedBehaviourSanitizer support
- `BUILD_TSAN=1`  - Build with ThreadSanitizer support
- `BUILD_LIBFUZZER=1`  - Build with LibFuzzer instrumentation, see section below

## Running a test
The darwintest executable is created in `tests/unit/build/sym/`. To run all tests in an executable:

```
> ./tests/unit/build/sym/<test-name>
```

## Creating a new test
- Add a `<test-name>.c` file in this folder (or a sub-folder) with the test code.
- In the added .c file, add a line that looks like `#define UT_MODULE osfmk`
This determines the context in which the test is going to be built. This should be
either "bsd" or "osfmk", depending on where the tested code resides. See example_test_bsd.c, example_test_osfmk.c.
- Tests can be added in a sub-folder of tests/unit/. Folders are automatically discovered by the Makefile

### Building all tests
To build and run all the unit tests executables do:
```
> make -C tests/unit SDKROOT=macosx.internal install
> ./tests/unit/build/sym/run_unittests.sh
```
Another option is to run through the main Makefile:
```
> make SDKROOT=macosx.internal xnu_unittests
> ./BUILD/sym/run_unittests.sh
```
This is what the xnu_unittests build alias builds. Notice that the output folder is different from the first option.

## Debugging a test
```
> xcrun -sdk macosx.internal lldb ./tests/unit/build/sym/<test-name>
(lldb) run <test-case>
```
Notice that if the test executable contains more than one `T_DECL()`s, libdarwintest is going to run each `T_DECL()`
in a separate child process, so invoking `run` in lldb without the name of a specific `T_DECL()` will debug just the top
level process and not stop on breakpoints.
For a better debugging experience wrap debugged code with 
```
#pragma clang attribute push(__attribute__((noinline, optnone)), apply_to=function)
...
#pragma clang attribute pop
```
or annotate individual functions with `__attribute__((noinline, optnone))`

The unit-tests Makefile is able to generate files that allow an easy debugging experience with various IDEs
```
> make SDKROOT=macosx.internal cmds_json
```
This make target adds the unit-tests executables that were built since the last `clean` to the `compile_commands.json`
file at the root of the repository so that IDEs that support this file (VSCode, CLion) know about the test .c files 
as well as the XNU .c files.

### Debugging with Xcode
```
> make SDKROOT=macosx.internal proj_xcode
```
This reads the `compile_commands.json` file and generates an Xcode project named `ut_xnu_proj.xcodeproj` with all of 
XNU and the unit-tests source files, and running schemes for the test targets.
To debug using this project:
- Start Xcode, open the `ut_xnu_proj.xcodeproj` project
- At the top bar, select the running scheme named after the test executable name (`<test-name>`)
- In the same menu, press "Edit Scheme", go to "Run"->"Arguments" and add as an argument the name of the `T_DECL()`
to debug
- Again at the top bar, to the right of the name of the scheme press `My Mac (arm64e)` to open the Location menu
- Select `My Mac (arm64)` (instead of `My Mac (arm64e)`)
- Set a breakpoint in the test
- Press the Play button at the top bar

### Debugging with VSCode
```
> make SDKROOT=macosx.internal proj_vscode
```
This reads the `compile_commands.json` file and generates a `.vscode/launch.json` file for VSCode to know about
the executables to run.
(if you have such existing file it will be overwritten)
To debug in VSCode:
- (one time setup) Install the "LLDB DAP" extension
  - the "LLDB DAP" extension uses the lldb from the currently selected Xcode.app
- Open the XNU root folder
- Press the "Run and Debug" tab at the left bar
- Select the test executable name from the top menu (`<test-name>`)
- Press the gear icon next to it to edit launch.json
- In "args", write the name of the `T_DECL()` to debug
- Press the green play arrow next to the test name

### Debugging with CLion
```
> make SDKROOT=macosx.internal proj_clion
```
This reads the `compile_commands.json` file and edits the files in `.idea` for CLion to know about
the executables to run.
To debug in CLion you need CLion version 2025.1.3 or above, which supports custom external lldb
- (one time setup) Add a new custom LLDB toolchain:
  - Open Settings -> "Build, Execution, Deployment" -> Toolchains
  - Press the "+" icon above the list
  - Name the new toolchain "System"
  - At the bottom, next to "Debugger:" add the path to an installed Xcode.app
  - (it doesn't have to be the Xcode.app which is currently selected or the one which is used to build XNU)
- Open the XNU root folder
- At the top right select the test executable name (`<test-name>`) from the menu
- Press the menu again "Edit Configurations..."
- Next to "Program arguments:" write the name of the `T_DECL()` to debug
- Press the bug icon to at the top right to debug

## Adding Mocks
A unit-test usually calls into functions in XNU, and those function may call other functions
which you may not be interested to test the functionality of, or may not work in user-space at all. 
This is what mocks are for.  
Any function in XNU can be replaced by a mock so that the test can redefine its implementation to suit its needs.
The recommended way to do this is using the private-mocks mechanism (pmocks):
- Read about how to use `T_MOCK_PRIVATE()` definitions in mocks/mock_dynamic.h.
- Add `__mockable` to the definition of the original function in XNU. This prevents the function from
  being inlined when XNU is built for unit-tests. An inlined function cannot be mocked.
- Add a section in your test that begin with `PMOCKS_START` and ends with `PMOCKS_END`
- Inside this section, add `T_MOCK_PRIVATE()` definitions for the functions your test needs to mock.
Building a test that does this generates an additional dylib called <test-name>.pmocks.dylib
which contains the test-specific mocks.

libmocks.dylib is a global library of mocks that are necessary the bootstrap process of all tests.
Developers of individual tests are discouraged from adding mocks to this library because this may lead to
unnecessary code conflicts and unexpected breakages.
Mock definitions can't exist in both libmocks.dylib and in a <test-name>.pmocks.dylib.
If you need to override a the functionality of mock that already exists in libmocks.dylib 
(.c files in tools/unit/mocks) use one of the T_MOCK_SET_*() macros from mock_dynamic.h 


## Running Coverage Analysis
### Run the unit-test make command with the coverage option:
```
> make -C tests/unit SDKROOT=macosx.internal BUILD_CODE_COVERAGE=1 <test-name>
```
This will build XNU, the mocks dylib and the test executable with coverage instrumentation.

### Run the unit-test and tell the coverage lib where to save the .profraw file:
```
> LLVM_PROFILE_FILE="coverage_data.profraw" ./tests/unit/build/sym/<test-name>
```

### Convert the .profraw file to .profdata file:
```
> xcrun -sdk macosx.internal llvm-profdata merge -sparse coverage_data.profraw -o coverage_data.profdata
```

### Generate reports

High-level per-file textual report:

```
> xcrun -sdk macosx.internal llvm-cov report ./tests/unit/build/sym/libkernel.development.t6020.dylib -instr-profile=coverage_data.profdata
```

Low-level per-line HTML pages in a directory structure:

```
> xcrun -sdk macosx.internal llvm-cov show ./tests/unit/build/sym/libkernel.development.t6020.dylib -instr-profile=coverage_data.profdata --format=html -output-dir ./_cov_html
> open ./_cov_html/index.html
```
Mind that both of these commands take the binary for which we want to show information, in this case, the XNU .dylib.
If you want to show the coverage for the unit-test executable, put that instead. It's also possible to specify multiple binaries with `-object` argument.

Both these commands can take `-sources` argument followed by the list of source files to limit the source files that would show in the report.
The names need to be the real paths of the files (relative or absolute), not just the path part that appears in the `report` output.

To check the coverage of a single function add `-name=<func-name>` to the `show` command.

To manually filter out functions from the report, for instance if the source file contains test functions which
are not interesting for coverage statistics:

- Add `-show-functions` to the `report` command and redirect the output to a file.
- From the output, take only the function names with:
`cat report_output.txt | cut -d " " -f1 | sort | uniq > func_names.txt`
- Edit the file and remove the functions names that are not needed.
Note that in this list, static functions appear with the filename as a prefix.
- Add the prefix `allowlist_fun:` to every line in the file:
`cat func_names.txt | sed 's/^/allowlist_fun:/' > allow_list.txt`
- Add the argument `-name-allowlist=allow_list.txt` to the `show` command.

### more documentation

https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
https://llvm.org/docs/CommandGuide/llvm-cov.html

## Deterministic threading with fibers
The mocks library provides a fibers implementation that can be used by tests including the header files in `mocks/osfmk/fibers/`.

To access mocks that replace locking and scheduling APIs like lck_mtx_t and waitq functions, the test file must include `mocks/mock_thread.h`
and use the `UT_USE_FIBERS(1)` macro in the global scope.

By default, the context switch points are placed the entry and exit of the fibers API (e.g. before and after mutex lock) but preemption can be simulated using compiler instrumentation.
If you add `FIBERS_PREEMPTION=1` to the make command line, every memory load and store in the XNU library and in your test file will be instrumentated to be
a possible context switch point for the deterministic scheduler.

In addition, a data race detector can be enabled when the test is using fibers with preemption simulation.
The checker is a probabilistic data race sanitizer based on the [DataCollider](https://www.usenix.org/legacy/event/osdi10/tech/full_papers/Erickson.pdf) algorithm and can be used as
a replacement of ThreadSanitizer (that works with the fibers implementation but there can be false positives) or in combination.
The checker can be enabled with the macro `UT_FIBERS_USE_CHECKER(1)` in the global scope of the test file or setting the `FIBERS_CHECK_RACES` env var when executing a test with fibers.

For an example test using fibers check `fibers_test.c`.

### Multi-CPU system simulation
By default the fibers operate assuming a single CPU system and scheduling is blocked when preemption is disabled, but this restricts the simulation to not exercise interleavings of threads possibly running on different CPUs.
Fibers scheduling with preemption disabled can be enabled using a multi-cpu system through the `UT_CPU_COUNT` macro.

For an example test using fibers with multiple simulated CPUs check `fibers_multicpu_test.c`.

## Fuzzing
The XNU user-space unit-tests framework offers fuzzing capabilities bridging darwintest with LibFuzzer.
Fuzzing harnesses can be written using the `T_FUZZ` declaration instead of the standard `T_DECL` and, by default, they run with a single fixed input and seed with a unit test like behaviour executing deterministically.
To switch to fuzzing mode, you need to explicitly provide at least one LibFuzzer argument to the command line.

For more details, check the [FUZZING.md](FUZZING.md) documentation file.

## FAQ
- Q: I'm trying to call function X but I get a linker error "Undefined symbols for architecture arm64e: X referenced from..."
- A: This is likely due to the function being declared as hidden, either using `__private_extern__` at
the function declaration or a `#pragma GCC visibility push(hidden)`/`#pragma GCC visibility pop` pair around
where it's defined. You can verify this by doing:
`nm -m tests/unit/build/obj/libkernel.development.t6020.dylib | grep <function-name>`
and verifying that the function in questions appears next to a lower-case `t` to mean it's a private symbol
(as opposed to a capital `T` which means it's exported symbol, or it not appearing at all which means there is
no such function).
To fix that, simply change `__private_extern__` to `__exported_hidden` or the `#pragma` pair with
`__exported_push_hidden`/`__exported_pop`. These keep the visibility the same (hidden) for normal XNU build but
drop to the default (visible) for the user-mode build.


- Q: How to build XNU on-desk if it builds with warnings which are treated as errors?
- A: In the make command line add `BUILD_WERROR=0`. This will also turn off warnings-as-errors for the unit tests themselves.


- Q: LLDB startup takes a long time and shows many errors about loading symbols
- A: try doing `dsymForUUID --disable` to disable automatic symbol loading.
