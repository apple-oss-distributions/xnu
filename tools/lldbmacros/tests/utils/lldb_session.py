##
# Copyright (c) 2025 Apple Inc. All rights reserved.
#
# @APPLE_OSREFERENCE_LICENSE_HEADER_START@
#
# This file contains Original Code and/or Modifications of Original Code
# as defined in and that are subject to the Apple Public Source License
# Version 2.0 (the 'License'). You may not use this file except in
# compliance with the License. The rights granted to you under the License
# may not be used to create, or enable the creation or redistribution of,
# unlawful or unlicensed copies of an Apple operating system, or to
# circumvent, violate, or enable the circumvention or violation of, any
# terms of an Apple operating system software license agreement.
#
# Please obtain a copy of the License at
# http://www.opensource.apple.com/apsl/ and read it before using this file.
#
# The Original Code and all software distributed under the License are
# distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
# EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
# INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
# Please see the License for the specific language governing rights and
# limitations under the License.
#
# @APPLE_OSREFERENCE_LICENSE_HEADER_END@
##

import contextlib
import functools
import typing
import time
from pathlib import Path
import lldb
from constants import EXECUTABLES_FOLDER, XNU_ROOT
from build_utils import build_unit_test

CHECKPOINT_GLOBAL_VARIABLE = 'lldb_current_checkpoint_name'
TIMEOUT_FOR_EXIT = 5.0
DEBUGGER_ENV = 'UT_IN_LLDB_SESSION'

_session_compiled_executables = set()
skip_build = False


def set_skip_build(skip: bool):
    global skip_build
    skip_build = skip


def with_lldb_session(exe_file: str, test_name: str):
    """Decorator that automatically creates LLDB session with executable and test name.
    
    Usage:
        @with_lldb_session("test_memory_macros", "test_showmap_summary_basic")
        def test_function(self, session):
            result = session.exec("some_macro")
            # ... test logic
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            global _session_compiled_executables, skip_build
            executable_path = EXECUTABLES_FOLDER / exe_file
            
            # Build the executable if needed
            if not skip_build:
                if exe_file not in _session_compiled_executables:
                    print(f"\n=== Building {exe_file} ===")
                    try:
                        build_unit_test(exe_file)
                        _session_compiled_executables.add(exe_file)
                        print(f"✓ Successfully built {exe_file}")
                    except Exception as e:
                        print(f"✗ Failed to build {exe_file}: {e}")
                        raise RuntimeError(f"Failed to build executable {exe_file}: {e}")
            else:
                print(f"Skipping build for {exe_file} (--skip-build flag enabled)")
            
            # For instance methods, self is args[0]
            # For regular functions, no self
            if args and hasattr(args[0], '__class__'):
                # This is a method call
                self_arg = args[0]
                other_args = args[1:]
                
                with LLDBGdbSession.create_with_executable(str(executable_path), test_name) as session:
                    return func(self_arg, session, *other_args, **kwargs)
            else:
                # This is a regular function
                with LLDBGdbSession.create_with_executable(str(executable_path), test_name) as session:
                    return func(session, *args, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    
    return decorator

class LLDBGdbSession:
    """LLDB session wrapper for executing commands and managing debugging state.
    
    This class provides a high-level interface for LLDB operations, including
    command execution with optional caching, variable lookup, and process management.
    
    Attributes:
        use_cache (bool): Controls whether LLDB command execution uses LRU caching.
            When True (default), commands are cached for performance
            When False, commands are executed fresh each time
    """
    
    def __init__(self, interpreter, test_name=None, use_cache=True):
        self._command_interpreter = interpreter
        self.target = None
        self.test_function_name = test_name
        self.use_cache = use_cache
        self._last_checkpoint = None  # Track the last checkpoint we stopped at

    def refresh(self):
        macros_base_path = XNU_ROOT / 'tools' / 'lldbmacros'
        self.exec('settings set target.load-script-from-symbol-file false')
        self.exec(f'settings set target.process.python-os-plugin-path {macros_base_path}/core/operating_system.py')
        self.exec(f'command script import {macros_base_path}/xnu.py')
        return self

    @classmethod
    @contextlib.contextmanager
    def create(cls, gdb_remote: typing.Optional[str]) -> 'LLDBGdbSession':
        debugger = lldb.SBDebugger.Create()
        command_interpreter = debugger.GetCommandInterpreter()

        session = LLDBGdbSession(command_interpreter)
        session.exec('settings set plugin.dynamic-loader.darwin-kernel.load-kexts false')

        session.refresh()
        with session._gdb(gdb_remote):
            yield session

        lldb.SBDebugger.Destroy(debugger)

    @classmethod
    @contextlib.contextmanager
    def create_with_executable(cls, executable_path: str, test_name: str) -> 'LLDBGdbSession':
        """Create session with a test executable loaded"""
        debugger = lldb.SBDebugger.Create()
        debugger.SetAsync(False)
        
        # Load XNU macros
        ci = debugger.GetCommandInterpreter()
        ret = lldb.SBCommandReturnObject()
        # Enable automatic loading of Python scripts embedded in symbol files
        # This allows XNU debugging scripts to be automatically loaded with test executables
        ci.HandleCommand("settings set target.load-script-from-symbol-file true", ret)
        
        # The output of commands ran with HandleCommand() is placed in lldb.SBCommandReturnObject(), so ret needs to be checked for the result
        if not ret.Succeeded():
            raise RuntimeError(f"Failed to load XNU macros: {ret.GetError()}")
        
        session = LLDBGdbSession(ci, test_name, use_cache=False)

        # Disable automatic kext loading to avoid interference with unit test environment
        # Unit tests should run in isolation without loading additional kernel extensions
        session.exec('settings set plugin.dynamic-loader.darwin-kernel.load-kexts false')
        # Refresh is needed to ensure XNU macros are properly loaded after session creation
        # and kext loading configuration, making debugging commands available for tests
        session.refresh()
        
        process = None
        try:
            session.target = debugger.CreateTargetWithFileAndArch(executable_path, None)
            if not session.target.IsValid():
                raise RuntimeError(f"Failed to create target: {executable_path}")
            
            # Prepare launch arguments - include test name
            args = ["-n", test_name]
            launch_info = lldb.SBLaunchInfo(args)
            
            # Set environment variable to indicate we're in an LLDB session
            launch_info.SetEnvironmentEntries([f"{DEBUGGER_ENV}=1"], True)
            
            error = lldb.SBError()
            process = session.target.Launch(launch_info, error)
            if not process.IsValid() or error.Fail():
                error_msg = error.GetCString() if error.Fail() else "Unknown error"
                raise RuntimeError(f"Failed to launch process: {error_msg}")
             
            yield session
            
            # Wait for process to exit after test completes
            session.wait_until_exit()
                
        finally:
            if process and process.IsValid():
                process.Kill()
            lldb.SBDebugger.Destroy(debugger)

    @functools.lru_cache(maxsize=5096)
    def _exec_cached(self, cmd) -> str:
        """Internal cached version of exec."""
        return self._exec_impl(cmd)
    
    def _exec_impl(self, cmd) -> str:
        """Internal implementation of exec command."""
        print(f'LLDBSession running command: `{cmd}`')
        res = lldb.SBCommandReturnObject()
        self._command_interpreter.HandleCommand(cmd, res)
        if res.Succeeded():
            return res.GetOutput()
        raise RuntimeError(res.GetError())
    
    def exec(self, cmd) -> str:
        """Execute LLDB command with optional caching.
        
        Args:
            cmd: LLDB command to execute
            
        Returns:
            str: Command output
            
        Raises:
            RuntimeError: If command fails
        """
        if self.use_cache:
            return self._exec_cached(cmd)
        else:
            return self._exec_impl(cmd)

    def _get_global_variable(self, variable_name: str):
        """Get a global variable as an SBValue object.
        
        This provides direct access to the LLDB SBValue object for maximum flexibility.
        
        Args:
            variable_name: Name of the global variable in the C executable
            
        Returns:
            lldb.SBValue or None: The variable as an SBValue object, or None if not found
        """
        var_list = self.target.FindGlobalVariables(variable_name, 1)
        if var_list.GetSize() > 0:
            var = var_list.GetValueAtIndex(0)
            if var.IsValid():
                return var
        
        return None

    def _get_local_variable(self, variable_name: str):
        """Get a local variable as an SBValue object from the unit test function.
        
        This provides direct access to the LLDB SBValue object for maximum flexibility.
        Searches for the variable in the unit test function frame.
        
        Args:
            variable_name: Name of the local variable
            
        Returns:
            lldb.SBValue or None: The variable as an SBValue object, or None if not found
        """
        process = self.target.GetProcess()
        if not process.IsValid():
            return None
        
        thread = process.GetSelectedThread()
        if not thread.IsValid():
            return None
        
        if not self.test_function_name:
            return None
        
        compiled_function_name = f"testmain_{self.test_function_name}"
        
        # Look for the unit test function in the call stack
        # Since ut_lldb_check_point is inline, we need to look beyond the current frame
        for frame_idx in range(thread.GetNumFrames()):
            frame = thread.GetFrameAtIndex(frame_idx)
            if not frame.IsValid():
                continue
                
            function = frame.GetFunction()
            if not function.IsValid():
                continue
            func_name = function.GetName()

            # Check if we're in the target test function
            if func_name == compiled_function_name:
                # If this frame is inlined, we need to look at the next frame for local variables
                if frame.IsInlined():
                    continue
                else:
                    # This is the actual function frame, not inlined
                    var = frame.FindVariable(variable_name)
                    if var.IsValid():
                        return var
        
        return None

    def get_variable(self, variable_name: str):
        """Get a variable as an SBValue object.
                
        This provides direct access to the LLDB SBValue object for maximum flexibility.
        Tries local variables first, then global variables if local lookup fails.
        
        Args:
            variable_name: Name of the variable in the C executable
            
        Returns:
            lldb.SBValue: The variable as an SBValue object
            
        Raises:
            RuntimeError: If variable not found in either local or global scope
        """
        # Try local first, then global if local fails
        var = self._get_local_variable(variable_name)
        if var:
            return var
            
        var = self._get_global_variable(variable_name)
        if var:
            return var
            
        # Both failed
        raise RuntimeError(f"Couldn't find global or local variable '{variable_name}'")

    def run_script(self, script_cmds):
        """Execute Python using LLDB script command and return output"""
        import_cmd = "from xnu import *"
        script_code = "; ".join(cmd for cmd in script_cmds)
        command = f"script {import_cmd};{script_code}"
        
        res = lldb.SBCommandReturnObject()
        self._command_interpreter.HandleCommand(command, res)
        if res.Succeeded():
            return res.GetOutput()
        raise RuntimeError(res.GetError())

    @contextlib.contextmanager
    def _gdb(self, remote_gdb: typing.Optional[str] = None) -> 'LLDBGdbSession':
        if remote_gdb is None:
            yield self
            return

        self.exec(f'gdb {remote_gdb}')
        yield self
        self.exec('detach')

    def run_until_checkpoint(self, target_string):
        """Run the process until it hits a __builtin_debugtrap() checkpoint with a specific string.

        Args:
            target_string: The format string to look for
        
        Returns:
            bool: True if stopped at the target checkpoint, False otherwise
        """
        if not self.target:
            raise RuntimeError("No target available")
            
        process = self.target.GetProcess()
        if not process.IsValid():
            raise RuntimeError("No valid process")
 
        while True:
            # Check current state
            state = process.GetState()
            if state == lldb.eStateStopped:
                # Check what checkpoint we're at
                current_string = self._get_checkpoint_format_string()
                if current_string == target_string:
                    print(f"Found target checkpoint: '{current_string}'")
                    self._last_checkpoint = current_string
                    return True
                elif current_string == self._last_checkpoint:
                    # We're still at the same checkpoint from a previous call - continue execution
                    process.Continue()
                else:
                    # We hit a new checkpoint that's not our target - raise RuntimeError
                    raise RuntimeError(f"Found checkpoint {current_string} instead of {target_string}")

            elif state == lldb.eStateRunning:
                process.WaitForProcessToStop(0.5)
            else:
                raise RuntimeError(f"Process terminated (state: {state}) without finding target checkpoint '{target_string}'")

    def wait_until_exit(self):
        """Wait for the process to exit naturally, ensuring no more checkpoints are hit.
        
        This method continues the process and waits for it to terminate normally,
        which is useful for ensuring test completeness and that no unexpected
        checkpoints are encountered after the test logic is complete.
            
        Raises:
            RuntimeError: If process does not exit gracefully
        """
        if not self.target:
            raise RuntimeError("No target available")
            
        process = self.target.GetProcess()
        if not process.IsValid():
            raise RuntimeError("No valid process")
        
        process.Continue()
        
        # Wait for process to finish or timeout
        start_time = time.time()
        state = None  # Initialize state variable
        while time.time() - start_time < TIMEOUT_FOR_EXIT:
            state = process.GetState()
            if state == lldb.eStateExited:
                return
            elif state == lldb.eStateStopped:
                # Process stopped - check if it's at a checkpoint
                current_checkpoint = self._get_checkpoint_format_string()
                if current_checkpoint:
                    raise RuntimeError(f"Process stopped at unexpected checkpoint '{current_checkpoint}' instead of exiting")
                else:
                    # Stopped for some other reason, continue
                    process.Continue()
            elif state == lldb.eStateRunning:
                time.sleep(0.1)
            else:
                # Some other terminal state
                raise RuntimeError(f"Process terminated unexpectedly with state: {state}")
        
        # Timeout occurred
        raise RuntimeError(f"Reached timeout without process exiting. Process is at state: {state}")

    def _get_checkpoint_format_string(self):
        """Get the format string from the current checkpoint.
        
        Returns:
            str: The format string, or None if not available
        """
        
        var = self._get_global_variable(CHECKPOINT_GLOBAL_VARIABLE)
        if not var:
            raise RuntimeError(f"Global variable '{CHECKPOINT_GLOBAL_VARIABLE}' not found")
        
        return var.GetSummary().strip('"')
