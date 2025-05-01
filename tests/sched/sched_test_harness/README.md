# Scheduler Test Harness

## Overview
The scheduler test harness makes it possible to test scheduler policy code deterministically from within a userspace binary, without the need to build and flash a kernelcache or even run on a test device. The idea is to compile the scheduler code-under-test in isolation from the rest of XNU, mocking out unneeded system and machine-layer functionality, so that the end result is a regular binary that we can validate and debug with as much ease as a typical userspace program.

## Dependency-Breaking Techniques Used in the Harness
The main challenge in compiling XNU scheduler code this way has been in unraveling dependencies that would grow the amount and complexity of code compiled by the test harness. We want to keep the mocking surface small while at the same time become able to test more and more scheduler logic with the harness. The following techniques have been helpful to limit the size of the mocking layer and minimize code duplication:

#### Conditional compilation with `SCHED_TEST_HARNESS` macro guard
In files containing code-under-test, we can avoid compiling unneeded symbols and includes with the guard `#if !SCHED_TEST_HARNESS`. We can also explicitly compile-in sections of needed symbols which are otherwise guarded-out for a userspace program, for example with `#if MACH_KERNEL_PRIVATE || SCHED_TEST_HARNESS`.

#### Control the header search paths with `clang -I` and overwrite unneeded header files
In `Makefile`, we specify a search order that prioritizes the headers in our mocking layer in `shadow_headers` first, before searching the actual XNU source (just under `osfmk/`). Then for a list of headers included by our code-under-test but not actually needed by the test harness, we can create empty versions of those headers in `shadow_headers` to prevent the real headers from being compiled into the test harness. We can also create custom versions of needed headers, containing only symbols used in the test harness.

## Harness Layout

### Interfaces Called by Tests
#### Runqueue Policy
Tests can use functionality laid out in `sched_runqueue_harness.h` to validate implementations of thread timesharing in the scheduler. For example, tests can create mock threads and thread groups, enqueue threads on a runqueue, and dequeue threads to validate the order in which they will receive CPU time. `sched_runqueue_harness.c` implements the interface by adding debug logging and then calling functions laid out in `sched_harness_impl.h`.

#### Migration Policy
Tests can use functionality laid out in `sched_migration_harness.h` to validate implementations of a migration policy that determines which cluster/CPU a thread will run on. For example, tests can create a mock HW topology and validate which clusters the scheduler would send certain threads to run on, based on the state of each of the clusters. Note, the migration harness depends on and includes the runqueue harness. `sched_migration_harness.c` implements the interface by adding debug logging and then calling functions laid out in `sched_harness_impl.h`.

#### Convenience Wrappers
`sched_policy_darwintest.h` contains convenience wrappers for certain libdarwintest functionality, for example to specially annotate test output and to prepend the name of a specific scheduler policy-under-test to the test case name. A test can specify the name of its policy-under-test using the `TEST_RUNQ_POLICY` define.

#### Implementation-Specific Interfaces
Clutch and Edge are the two scheduler policies currently testable using the harness. They each publish a custom test interface in `sched_clutch_harness.h` and `sched_edge_harness.h` respectively, so that unit tests can reference the values of certain tunables and defines present in the policy implementation.

### Interfaces Called by the Harness
#### Implementation-Specific Interfaces
 The Edge harness implementation also calls some functionality published by `sched_clutch_harness.h`, to avoid code duplication (as the real Edge policy depends on and nests with the Clutch policy). `sched_clutch_harness.c`, `sched_clutch_harness_impl.c`, and `sched_edge_harness.c` each implement their respective custom interfaces (`sched_clutch_harness.h` and `sched_edge_harness.h`), along with implementing all of the functionality in `sched_harness_impl.h` which they choose to support for testing.
