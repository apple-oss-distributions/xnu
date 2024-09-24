# LLDB macro testing

How to work with bundled unit test framework.

Be careful when touching common framework code. For larger changes, ask the Platform Triage team to
validate that the changes work in their environment before integration.

Unit-test architecture supports two kinds of tests:

- Standalone unit test \
  `tools/lldbmacros/tests/standalone_tests`
- LLDB based unit test \
  `tools/lldbmacros/tests/lldb_tests`

**Standalone** unit tests replace _lldb_ and _lldbwrap_ modules with _MagicMock_
instances. All tests in this location must not depend on LLDB.

**LLDB** unit tests are run from LLDB's python interpreter. It is possible to
access debugger/process/target from such test or invoke LLDB commands. This
way a test can exercise full stack including SBAPI and expression handlers.

## How to run tests

Standalone tests do not need LLDB and can be run with:
```sh
PYTHON=tools/lldbmacros python3 tools/lldbmacros/tests/runtest.py <kernel>
```

To run all tests (including LLDB based ones) a developer has to install
XCode and configure properly Python's path:

```sh
PYTHONPATH="tools/lldbmacros:`xcrun --toolchain ios lldb -P`"xcrun --toolchain ios python3 tools/lldbmacros/tests/runtest.py <kernel>
```

Default runner supports few options:

  * `-v` enables verbose output from unit test framework
  * `-d` enables debug logging and more detailed exception reports
  * `-c <path>` outputus HTML coverage if `coverage` module is installed

## Mocking framework

The goal of the mocking framework is to enhance existing mocking solutions
rather than building completely new framework. A test should still rely on
`unittest.mock` and cover specific needs with additional mocks provided by
this framework.

A test developer has three options how to handle mocking in a test:

* `unittest.mock` that covers general purpose Python mocking.
* `lldbmock.valuemock` designed to mock away `value` class instances.
* `lldbmock.memorymock` designed to provide real object in target's memory.

Examples of usage can be found in: \
    `tools/lldbmacros/tests/lldb_tests/test_examples.py`

### lldbmock.valuemock

A very simple mocking designed for replacing a `value` class instance or
some similar construct in the code.

The `ValueMock` class parses given `SBType` and recreates recursively whole
hierarchy of `MagicMock` instances. Final result looks like a value class but
it does not implement any value class logic or methods.

It does not perform any extra logic to handle special types like `union`.
A developer has to correctly populate all members that overlap because this
mock treats all such members as unique.

Auto generating mock specification from kernel under test allows checking that
all referenced members do exist in the final binary. Broken reference will
result either in test or tested code failure.

### lldbmock.memorymock

The goal of memory mock is to provide easy to use interface for a test developer
to describe object in target's memory. From technical perspective this is a data
serializer that reflects memory location and representation of given SBType's
members.

The framework provides two kinds of mocks:

  * `RawMock` that is suitable to place unstructured data into target's memory.
  * `MemoryMock` that mirrors given `SBType` and serializes data into target's
    memory.

