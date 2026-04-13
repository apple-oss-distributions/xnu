# Fuzzing XNU user-space

In addition to unit tests, the XNU user-space framework can run fuzzers.

Fuzzing harnesses live in the `tests/unit/fuzzing` folder and run by default as unit tests. No fuzzing is done if no command line argument is specified.

## Building a harness:
```
> make -C tests/unit SDKROOT=macosx.internal fuzzing/<harness-name>
```

The process is the same as building tests, as described in the [README.md](README.md). 

`BUILD_LIBFUZZER=1` is a relevant customization for the makefile command as it builds XNU with Libfuzzer instrumentation and without it the fuzzer will not be able to collect coverage from XNU.

## Running a harness
The darwintest fuzzing harness is created in `tests/unit/build/sym/fuzzing/`.

### As a test
To run all the harness as unit tests simply don't use any test-specific argument.
```
> ./tests/unit/build/sym/fuzzing/<harness-name>
```

To run a specific test in the harness use the `-n` darwintest parameter:
 ```
> ./tests/unit/build/sym/fuzzing/<harness-name> -n <test-name>
```

### As a fuzzer
You need to provide at least one per-test specific argument to run in fuzzing mode. The most trivial one is to specify `max_len` and a corpus folder where the fuzzer testcases will be stored.

 ```
> mkdir -p ./corpus
> ./tests/unit/build/sym/fuzzing/<harness-name> -n <test-name> -- -max_len=65536 ./corpus
```

The test-specific arguments are passed to Libfuzzer, check the Libfuzzer documentation for more info: https://llvm.org/docs/LibFuzzer.html#options

## Creating a new harness
- Add a `<harness-name>.c` file to the `fuzzing/` folder (or a sub-folder) and follow the same setup of a unit test including the [`mocks/unit_test_fuzz.h`](mocks/unit_test_fuzz.h) header file.
- To define fuzzing test entries use `T_FUZZ` instead of the classic `T_DECL`. In a `T_FUZZ` you will be able to access the fuzzer-produced buffer defined as: `const uint8_t* data, size_t size`
- In fuzzing mode, the body of the fuzzing test entry will be executed many times, be sure to avoid memory leaks and if you need to execute some init code just once before the fuzzer starts define a `T_FUZZ_INIT` using the same name used for the fuzzing test entry.

### Advanced: custom mutators
Instead of letting Libfuzzer produce the input with its own mutator, the user can define a custom mutator with a `T_FUZZ_MUTATOR` declaration.
Check [`mocks/unit_test_fuzz.h`](mocks/unit_test_fuzz.h) and the [`vm_operations.c`](fuzzing/vm_operations.c) harness as reference.

## Fuzzing with fibers
The deterministic scheduler built on top of fibers and available in the mocks library can be used in combination with fuzzing.

The immediate benefit is determinism, concurrency-related bugs found by the fuzzer are 100% reproduce rate as long as the executed code in XNU is determinisc too. Many functions like `RandomULong` are already mocked but you may need to add mocks if the code under test is not deterministic. Use the PRNG in `mocks/fibers/random.h`.

To acheive this only, simply used a fixed PRNG seed or consume it from the fuzzer input. `random_set_seed` is all you need.

Note: for the purpose of determinism, you want also to add a call to `fibers_reset_state` at the beginning of the harness to restart the fibers state (and the multi-cpu state if enabled) at every iteration.

However, in addition, there are several challenges related to fuzzing concurrent code that can be solved with fibers.

#### Fuzzer-controlled scheduling
The complete control over scheduling decisions can be combined with a fuzzer to explore different thread interleavings systematically and mutate it.
The fibers provide an API to replace the scheduler and the mocks library provides and alternative scheduler to the default one (decisions based on a PRNG) built for fuzzing.

```c
// The fuzzer data can be split into parts:
// - Input for fiber 1 operations
// - Input for fiber 2 operations  
// - Scheduling decisions (which fiber runs when)

fibers_fuzzing_scheduler_setup(scheduling_buffer, scheduling_size);
```

The scheduler consumes bytes from the scheduling buffer to decide which fiber to run next at each context switch point. Mutations on the scheduling buffer will result in testcases having the same interleaving till the mutations point allowing the fuzzer to explore the interleavings better.

#### Advanced: interleaving feedback
While controlling the scheduler using the fuzzer output is beneficial, it has more impact when coupled with some sort of feedback about the exploration the the thread interleavings, just like traditional fuzzers explore code coverage.

To do so, framework provides a feedback mechanism based on reads-from relationships between fibers:

1. When a fiber writes to a memory object, the framework records: `(memory_object -> write_location, fiber_id)`
2. When a different fiber reads from the same memory object, it:
   - Retrieves the last write_location for that object
   - Computes a coverage index from the tuple: `(write_location, read_location)`
   - Adds this to LibFuzzer's coverage map
3. This rewards the fuzzer for discovering new reads-from relationships across fibers

This mechanism traces inter-fiber data flow and helps the fuzzer discover concurrency patterns and potential data race scenarios.

To enable this, `fibers_fuzzing_feedback_setup` must be called from a `T_FUZZ_INIT` and `fibers_fuzzing_feedback_reset` at the beginning of the `T_FUZZ` body so that the feedback is reset at every execution.

Note: if the code under test is huge, the coverage feedback will be massive and the thread interleavings feedback too (more code = more memory operations). If the fuzzer ends up in state explosion consider disabling either coverage of interleavings feedback depending on the nature of the code under test.

### Building with preemption simulation
To maximize interleaving exploration, you can enable preemption simulation:

```bash
make -C tests/unit SDKROOT=macosx.internal FIBERS_PREEMPTION=1 BUILD_LIBFUZZER=1 fuzzing/<harness-name>
```

With `FIBERS_PREEMPTION=1`:
- Every memory load/store becomes a potential context switch point
- This is achieved through compiler instrumentation
- Simulates realistic preemptive scheduling where interrupts can occur at any instruction
- Use `ATTR_NO_SANCOV` attribute to disable instrumentation for specific functions. NOTE: calls to other functions may still trigger preemption events, to completely disable it at runtime use `fibers_current->may_yield_disabled++` and re-enabled it later with `fibers_current->may_yield_disabled--`.

## FAQ
- Q: As fuzzing harnesses run as unit tests, this means that the unit tests runs can have flaky results?
- A: No, the harnesses in unit-test mode run with a fixed seed and are deterministic as long the called code it is, so exactly like unit tests.

- Q: Why fuzzing harnesses are always built and run alongside all the unit tests?
- A: The reason behind this choice is to ensure maintanability. Changing XNU or the unit-tests framework in a breaking way for the harness will trigger and error. In addition, running a harness as a unit test, even if less powerful than in fuzzing mode, can help spot introduced bugs.

- Q: I am using the fibers deterministic scheduler but I cannot reproduce crashes
- A: Some harnesses may have initializion code run only during the first execution and this can change the thread scheduling,
if this si the case the solution is simple: execute the given crashing testcase 2 times with something like
```
./tests/unit/build/sym/fuzzing/<harness-name> -n <target-name> -- ./crash-XXXX ./crash-XXXX 
```
