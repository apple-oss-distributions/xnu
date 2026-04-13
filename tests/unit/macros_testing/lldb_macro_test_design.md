# LLDB Macro Testing with pytest

## Overview

This document describes a pytest-based testing system for LLDB macros used in kernel debugging. The system tests macros
by creating user-space executables that simulate kernel data structures, then running LLDB macros against these
controlled test environments.

## Architecture

The testing system has these main components:

1. **pytest Test Runner**: Discovers and runs tests using standard pytest framework
2. **LLDB Session Manager**: Creates and manages LLDB debugger instances with XNU macros
3. **Test Executables**: libdarwintest-based C programs that create realistic kernel scenarios
4. **Session Utilities**: Helper classes for LLDB command execution and output validation

## Core Components

### Test Executables (`tests/unit/macros_testing/`)

**libdarwintest-based C executables**:
- Link against kernel code to create authentic data structures
- Use libdarwintest framework for test organization
- Set up specific kernel scenarios (vm_map, task structures, etc.)

Example: `test_memory_macros.c` creates vm_map structures for memory macro testing.

### LLDB Session Management (`tools/lldbmacros/tests/utils/lldb_session.py`)

**LLDBGdbSession**:
- Manages LLDB debugger creation and destruction
- Automatically loads XNU macros from `tools/lldbmacros/xnu.py`
- Supports checkpoint-based debugging with `ut_lldb_check_point()` functions
- Provides command execution interface with variable address resolution

**Key Features**:
- `create_with_executable()`: Creates session with specific test executable
- `exec(cmd)`: Executes LLDB commands with caching controlled by session configuration
- `run_until_checkpoint(target_string)`: Stops execution at specific checkpoint
- `get_variable(name)`: Access variables with scope resolution (tries local first, then global)
- Automatic cleanup and resource management

### Checkpoint Infrastructure (`tests/unit/macros_testing/`)

**Checkpoint Functions**:
- `ut_lldb_check_point(checkpoint_name)`: Places named breakpoints in test code using `__builtin_debugtrap()`

**Features**:
- Cross-platform breakpoint generation using `__builtin_debugtrap()`
- String-based checkpoint identification
- Process state management and continuation
- Call stack traversal for checkpoint detection

## Test Workflow

1. **Test Discovery**: pytest discovers test files matching `tools/lldbmacros/tests/test_*.py` pattern
2. **Build Process**: Executables are built automatically per-test by the `@with_lldb_session` decorator with session-level caching, or use `--skip-build` flag to skip building entirely
3. **LLDB Session Creation**: Create session with test executable and function name using `@with_lldb_session` decorator
4. **Checkpoint Execution**: Use `run_until_checkpoint("checkpoint_name")` for targeted stops
5. **State Inspection**: Access variables at specific execution points using `get_variable()`
6. **State Verification**: Validate data structure changes between checkpoints
7. **Macro Execution**: Run LLDB macros using `session.exec()` method

## Running Tests

### Command Line Execution
First, install pytest if not already available:
```bash
# This would install pytest for the current user only, in /Users/user/Library/Python
pip3 install pytest
```
Then run the tests:
```bash
# Run specific test file (builds executables automatically as needed)
# Note: -s flag disables pytest's output capturing for debugging tests with print statements.
# Should not be used in normal runs or CI/CD environments.
xcrun -sdk macosx.internal python3 -m pytest ./tools/lldbmacros/tests/test_memory.py -s

# Run with verbose output
xcrun -sdk macosx.internal python3 -m pytest ./tools/lldbmacros/tests/test_memory.py -s -v

# Run specific test method
xcrun -sdk macosx.internal python3 -m pytest ./tools/lldbmacros/tests/test_memory.py::TestMemory::test_showmap_function -s

# Skip building executables (use existing ones)
xcrun -sdk macosx.internal python3 -m pytest ./tools/lldbmacros/tests/ --skip-build -s
```

### Build Process

Test executables are built automatically by the `@with_lldb_session` decorator with intelligent session-level caching:
- **Default behavior**: Each executable is built once per pytest session when first needed
- **Session tracking**: If an executable was already built in the current session, building is skipped
- **Skip building**: Use `--skip-build` flag to skip all building and use existing executables
- **Build command**: Runs `make -C tests/unit SDKROOT=macosx.internal macros_testing/{executable_name}`
- **Output location**: Built executables are placed in `tests/unit/build/sym/macros_testing/`


## Benefits

- **Realistic Testing**: Uses actual kernel code and data structures
- **Isolated Environment**: Each test runs in its own LLDB session
- **Automated Building**: Test executables built on-demand

## Example Tests

### Checkpoint-Based Test
```python
import sys
import json
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'utils'))
from lldb_session import with_lldb_session

MY_UNIT_TEST_EXE = 'some_unit_test_exe'

class TestCheckpoint:
    @with_lldb_session(MY_UNIT_TEST_EXE, "test_function_name")
    def test_state_changes(self, session):
        """Test state changes between checkpoints."""
        # Stop at first checkpoint
        session.run_until_checkpoint("checkpoint1")
        command = "some_macro"
        val = session.get_variable("my_variable").value
        assert val == 10
        result1 = session.exec(f"{command} {val}")
        
        # Continue to second checkpoint
        session.run_until_checkpoint("checkpoint2")
        val = session.get_variable("my_variable").value
        assert val == 3
        result2 = session.exec(f"{command} {val}")
```

## Test Executable Example

### Checkpoint-Based Test Executable
```c
#include <darwintest.h>
#include "mocks/unit_test_utils.h"

T_DECL(test_function_name, "Test description with checkpoints") {
    int my_variable = 10;
    
    ut_lldb_check_point("checkpoint1");  // First checkpoint
    
    // Modify state
    my_variable = 3;
    
    ut_lldb_check_point("checkpoint2");  // Second checkpoint
}
```
