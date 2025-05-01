# Introduction
XNU's LLDB macros are tools to aid debugging the kernel.

There are several types of tests.

# Types of tests and how to run them
## ScriptedProcess
LLDB's ScriptedProcess enables creating a session for a given binary with artificial state.
For LLDB macros testing, this allows verifying assumptions about structs.
From the binary, LLDB knows about the fields of a struct, and test attempting to access them will fail if they've been
renamed or removed.
Theoretically a ScriptedProcess could be used to validate macros, but getting valid XNU state is an issue.

Run with e.g.
`PYTHONPATH=tools/lldbmacros xcrun --toolchain macos python3 tools/lldbmacros/tests/runtests.py BUILD/obj/DEVELOPMENT_ARM64_T6031/kernel.development.t6031`

## *Any* LLDB session smoke tests

To run the smoke LLDB tests within a LLDB session anywhere - either at-desk VM (quickest), at-desk machine or a coredump 
(takes much more time).

### Disclaimers 
1. There are some macros that are ignored, see `IGNORES` variable (xno/tools/lldbmacros/tests/integration_smoke/test_lldb_macros.py) for more information.
2. There are some macros that are skipped for now - we will add at a later time.
3. Validation occurs only for the exit code of the macro run, not for the output.

### Triggering the tests within a LLDB session (Live VM / Tethered device / Coredump)
1. `xcrun --sdk macosx.internal lldb [-c coredump file]`
2. `command script import <xnu_root>/tools/lldbmacros/tests/integration_smoke/test_lldb_macros.py`
-----
Notice! if you need a gdb-remote session, you will have to enter it manually before running the macros.
* `gdb <[host=127.0.0.1:]port>` (e.g. 8000 or 1.3.3.7:8000).
-----
3. `macro_exec [macro_1] [macro_2] [...]`
4. `macro_coverage`

### Triggering the tests from your local machine (at-desk) Live VM / Tethered Device
1. `xcrun --sdk macosx.internal python3 <xnu_root>/tools/lldbmacros/tests/integration_smoke/test_lldb_macros.py [[host=127.0.0.1:]<port>]`

### Triggering the tests with customizations (pytest) - Live VM / Tethered Device
1. `xcrun --sdk macosx.internal python3 -m pytest <pytest_options> [--gdb-remote [host=127.0.0.1:]<port>] <xnu_root>/tools/lldbmacros/tests/integration_smoke/test_lldb_macros.py <pytest_arguments>`
