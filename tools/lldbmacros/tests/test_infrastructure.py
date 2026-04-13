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

#!/usr/bin/env python3

"""
Comprehensive testing of LLDB macros testing infrastructure.

The @patch decorators in this file are used to mock external dependencies during unit testing.
When you use @patch('module.function'), it replaces the real function with a MagicMock object
that you can control and monitor. This allows tests to run without actually executing system
commands, making file system changes, or requiring external tools like LLDB to be installed.
The mock objects are passed as parameters to the test method in reverse order of decoration.

For example, @patch('build_utils.subprocess.run') replaces the real subprocess.run function
with a mock that can be programmed to return specific values (like returncode=0 for success
or returncode=1 for failure) without actually executing shell commands during testing.
"""

import sys
import os
import lldb
from unittest.mock import patch, MagicMock
import pytest

# Add utils to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'utils'))

# Import infrastructure components to test
from constants import XNU_ROOT, DEFAULT_SDKROOT, UNIT_TESTS_DIR, MACROS_TESTING_DIR
from build_utils import build_unit_test
from lldb_session import LLDBGdbSession


class TestBuildUtilities:
    """Test build utilities and decorators."""
    
    @patch('build_utils.subprocess.run')
    @patch('build_utils.os.chdir')
    @patch('build_utils.os.getcwd')
    def test_build_unit_test_success(self, mock_getcwd, mock_chdir, mock_run):
        """Test successful build_unit_test execution."""
        mock_getcwd.return_value = "/original/path"
        mock_run.return_value = MagicMock(returncode=0, stdout="Build successful", stderr="")
        
        # Test successful build
        build_unit_test("test_exe")
        
        # Verify make command was called correctly
        expected_cmd = [
            "make",
            "-C", UNIT_TESTS_DIR,
            f"SDKROOT={DEFAULT_SDKROOT}",
            f"{MACROS_TESTING_DIR}/test_exe"
        ]
        mock_run.assert_called_once()
        args, _ = mock_run.call_args
        assert args[0] == expected_cmd
        
        # Verify directory changes
        mock_chdir.assert_any_call(XNU_ROOT)
        mock_chdir.assert_any_call("/original/path")
    
    @patch('build_utils.subprocess.run')
    @patch('build_utils.os.chdir')
    @patch('build_utils.os.getcwd')
    def test_build_unit_test_failure(self, mock_getcwd, mock_chdir, mock_run):
        """Test build_unit_test failure handling.
        
        This test simulates a build failure by mocking the build process to return 1
        which means the build fail. The build_unit_test function should detect this failure
        condition and raise a RuntimeError with details about what went wrong.
        """
        mock_getcwd.return_value = "/original/path"
        mock_run.return_value = MagicMock(
            returncode=1,  # Non-zero return code simulates build failure
            stdout="Build output",
            stderr="Build error"
        )
        
        # Test build failure
        with pytest.raises(RuntimeError) as exc_info:
            build_unit_test("test_exe")
        
        assert "Build failed for test_exe" in str(exc_info.value)
        assert "Return code: 1" in str(exc_info.value)
        
        # Verify directory is restored even on failure
        mock_chdir.assert_any_call("/original/path")
    
class TestLLDBSessionManagement:
    """Test LLDB session management utilities."""
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_creation(self, mock_lldb):
        """Test LLDBGdbSession creation and basic functionality."""
        mock_debugger = MagicMock()
        mock_interpreter = MagicMock()
        mock_debugger.GetCommandInterpreter.return_value = mock_interpreter
        mock_lldb.SBDebugger.Create.return_value = mock_debugger
        
        # Test with all constructor parameters
        session = LLDBGdbSession(mock_interpreter, test_name="test_case", use_cache=True)
        assert session.test_function_name == "test_case"
        assert session.use_cache == True
        
        # Test exec method
        mock_result = MagicMock()
        mock_result.Succeeded.return_value = True
        mock_result.GetOutput.return_value = "test output"
        mock_interpreter.HandleCommand.return_value = None
        
        with patch('lldb_session.lldb.SBCommandReturnObject', return_value=mock_result):
            output = session.exec("test command")
            assert output == "test output"
            mock_interpreter.HandleCommand.assert_called_with("test command", mock_result)
    
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_exec_failure(self, mock_lldb):
        """Test LLDBGdbSession exec method failure handling."""
        mock_interpreter = MagicMock()
        session = LLDBGdbSession(mock_interpreter)
        
        # Test exec failure
        mock_result = MagicMock()
        mock_result.Succeeded.return_value = False
        mock_result.GetError.return_value = "Command failed"
        mock_interpreter.HandleCommand.return_value = None
        
        with patch('lldb_session.lldb.SBCommandReturnObject', return_value=mock_result):
            with pytest.raises(RuntimeError) as exc_info:
                session.exec("invalid command")
            assert "Command failed" in str(exc_info.value)
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_create_with_executable(self, mock_lldb):
        """Test LLDBGdbSession.create_with_executable class method."""
        mock_debugger = MagicMock()
        mock_interpreter = MagicMock()
        mock_target = MagicMock()
        mock_process = MagicMock()
        mock_launch_info = MagicMock()
        mock_error = MagicMock()
        
        mock_debugger.GetCommandInterpreter.return_value = mock_interpreter
        mock_debugger.CreateTargetWithFileAndArch.return_value = mock_target
        mock_target.IsValid.return_value = True
        mock_target.Launch.return_value = mock_process
        mock_process.IsValid.return_value = True
        mock_error.Fail.return_value = False
        
        # Configure mock_process.GetState() to return proper LLDB state constants
        mock_process.GetState.return_value = lldb.eStateExited
        
        # Configure mock_target.GetProcess() to return the mock_process
        mock_target.GetProcess.return_value = mock_process
        
        mock_lldb.SBDebugger.Create.return_value = mock_debugger
        mock_lldb.SBCommandReturnObject.return_value.Succeeded.return_value = True
        mock_lldb.SBLaunchInfo.return_value = mock_launch_info
        mock_lldb.SBError.return_value = mock_error
        
        # Mock the LLDB state constants
        mock_lldb.eStateExited = lldb.eStateExited
        mock_lldb.eStateStopped = lldb.eStateStopped
        mock_lldb.eStateRunning = lldb.eStateRunning
        
        with patch.object(LLDBGdbSession, 'refresh') as mock_refresh:
            with LLDBGdbSession.create_with_executable("/test/exe", "test_case") as session:
                assert isinstance(session, LLDBGdbSession)
                assert session.target == mock_target
                assert session.test_function_name == "test_case"
                assert not session.use_cache
                mock_refresh.assert_called_once()
                
                # Verify launch arguments include test name
                mock_target.Launch.assert_called_once_with(mock_launch_info, mock_error)
                mock_lldb.SBLaunchInfo.assert_called_once_with(["-n", "test_case"])
            
            mock_process.Kill.assert_called_once()
            mock_lldb.SBDebugger.Destroy.assert_called_once_with(mock_debugger)
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_get_global_variable(self, mock_lldb):
        """Test LLDBGdbSession._get_global_variable method."""
        mock_interpreter = MagicMock()
        mock_target = MagicMock()
        session = LLDBGdbSession(mock_interpreter)
        session.target = mock_target
        
        # Mock successful global variable lookup
        mock_var_list = MagicMock()
        mock_var = MagicMock()
        
        mock_target.FindGlobalVariables.return_value = mock_var_list
        mock_var_list.GetSize.return_value = 1
        mock_var_list.GetValueAtIndex.return_value = mock_var
        mock_var.IsValid.return_value = True
        
        result = session._get_global_variable("test_var")
        assert result == mock_var
        mock_target.FindGlobalVariables.assert_called_once_with("test_var", 1)
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_get_global_variable_not_found(self, mock_lldb):
        """Test LLDBGdbSession._get_global_variable when variable not found."""
        mock_interpreter = MagicMock()
        mock_target = MagicMock()
        session = LLDBGdbSession(mock_interpreter)
        session.target = mock_target
        
        # Mock failed global variable lookup
        mock_var_list = MagicMock()
        mock_target.FindGlobalVariables.return_value = mock_var_list
        mock_var_list.GetSize.return_value = 0
        
        result = session._get_global_variable("nonexistent_var")
        assert result is None
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_get_local_variable(self, mock_lldb):
        """Test LLDBGdbSession._get_local_variable method."""
        mock_interpreter = MagicMock()
        mock_target = MagicMock()
        mock_process = MagicMock()
        mock_thread = MagicMock()
        mock_frame = MagicMock()
        mock_function = MagicMock()
        mock_var = MagicMock()
        
        session = LLDBGdbSession(mock_interpreter, test_name="test_case")
        session.target = mock_target
        
        mock_target.GetProcess.return_value = mock_process
        mock_process.IsValid.return_value = True
        mock_process.GetSelectedThread.return_value = mock_thread
        mock_thread.IsValid.return_value = True
        mock_thread.GetNumFrames.return_value = 1
        mock_thread.GetFrameAtIndex.return_value = mock_frame
        mock_frame.IsValid.return_value = True
        mock_frame.IsInlined.return_value = False  # Not inlined
        mock_frame.GetFunction.return_value = mock_function
        mock_function.IsValid.return_value = True
        mock_function.GetName.return_value = "testmain_test_case"
        mock_frame.FindVariable.return_value = mock_var
        mock_var.IsValid.return_value = True
        
        result = session._get_local_variable("local_var")
        assert result == mock_var
        mock_frame.FindVariable.assert_called_once_with("local_var")
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_get_variable(self, mock_lldb):
        """Test LLDBGdbSession.get_variable method."""
        mock_interpreter = MagicMock()
        mock_target = MagicMock()
        mock_var = MagicMock()
        
        session = LLDBGdbSession(mock_interpreter)
        session.target = mock_target
        
        # Mock successful global variable lookup (local fails, global succeeds)
        with patch.object(session, '_get_local_variable', return_value=None):
            with patch.object(session, '_get_global_variable', return_value=mock_var):
                result = session.get_variable("test_var")
                assert result == mock_var
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_get_variable_not_found(self, mock_lldb):
        """Test LLDBGdbSession.get_variable when variable not found."""
        mock_interpreter = MagicMock()
        session = LLDBGdbSession(mock_interpreter)
        
        # Mock both local and global variable lookup failing
        with patch.object(session, '_get_local_variable', return_value=None):
            with patch.object(session, '_get_global_variable', return_value=None):
                with pytest.raises(RuntimeError) as exc_info:
                    session.get_variable("nonexistent_var")
                assert "Couldn't find global or local variable 'nonexistent_var'" in str(exc_info.value)
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_run_script(self, mock_lldb):
        """Test LLDBGdbSession.run_script method."""
        mock_interpreter = MagicMock()
        session = LLDBGdbSession(mock_interpreter)
        
        # Mock successful script execution
        mock_result = MagicMock()
        mock_result.Succeeded.return_value = True
        mock_result.GetOutput.return_value = "script output"
        mock_interpreter.HandleCommand.return_value = None
        
        with patch('lldb_session.lldb.SBCommandReturnObject', return_value=mock_result):
            result = session.run_script(["print('hello')", "x = 42"])
            assert result == "script output"
            # Verify the command format includes import and script commands
            expected_cmd = "script from xnu import *;print('hello'); x = 42"
            mock_interpreter.HandleCommand.assert_called_with(expected_cmd, mock_result)
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_run_script_failure(self, mock_lldb):
        """Test LLDBGdbSession.run_script method failure handling."""
        mock_interpreter = MagicMock()
        session = LLDBGdbSession(mock_interpreter)
        
        # Mock failed script execution
        mock_result = MagicMock()
        mock_result.Succeeded.return_value = False
        mock_result.GetError.return_value = "Script error"
        mock_interpreter.HandleCommand.return_value = None
        
        with patch('lldb_session.lldb.SBCommandReturnObject', return_value=mock_result):
            with pytest.raises(RuntimeError) as exc_info:
                session.run_script(["invalid_script"])
            assert "Script error" in str(exc_info.value)
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_run_until_checkpoint(self, mock_lldb):
        """Test LLDBGdbSession.run_until_checkpoint method."""
        mock_interpreter = MagicMock()
        mock_target = MagicMock()
        mock_process = MagicMock()
        
        session = LLDBGdbSession(mock_interpreter)
        session.target = mock_target
        
        mock_target.GetProcess.return_value = mock_process
        mock_process.IsValid.return_value = True
        mock_process.GetState.side_effect = [lldb.eStateStopped]
        mock_lldb.eStateStopped = 5
        mock_lldb.eStateRunning = 3
        
        with patch.object(session, '_get_checkpoint_format_string', return_value="target_checkpoint"):
            result = session.run_until_checkpoint("target_checkpoint")
            assert result
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_run_until_checkpoint_not_found(self, mock_lldb):
        """Test LLDBGdbSession.run_until_checkpoint when wrong checkpoint found."""
        mock_interpreter = MagicMock()
        mock_target = MagicMock()
        mock_process = MagicMock()
        
        session = LLDBGdbSession(mock_interpreter)
        session.target = mock_target
        session._last_checkpoint = None  # Initialize the checkpoint tracking
        
        mock_target.GetProcess.return_value = mock_process
        mock_process.IsValid.return_value = True
        mock_process.GetState.return_value = lldb.eStateStopped
        mock_lldb.eStateStopped = 5
        mock_lldb.eStateRunning = 3
        mock_lldb.eStateExited = 7
        
        with patch.object(session, '_get_checkpoint_format_string', return_value="different_checkpoint"):
            with pytest.raises(RuntimeError) as exc_info:
                session.run_until_checkpoint("target_checkpoint")
            assert "Found checkpoint different_checkpoint instead of target_checkpoint" in str(exc_info.value)
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_get_checkpoint_format_string(self, mock_lldb):
        """Test LLDBGdbSession._get_checkpoint_format_string method."""
        mock_interpreter = MagicMock()
        mock_target = MagicMock()
        mock_process = MagicMock()
        mock_thread = MagicMock()
        mock_frame = MagicMock()
        mock_function = MagicMock()
        mock_var = MagicMock()
        
        session = LLDBGdbSession(mock_interpreter)
        session.target = mock_target
        
        mock_target.GetProcess.return_value = mock_process
        mock_process.GetSelectedThread.return_value = mock_thread
        mock_thread.IsValid.return_value = True
        mock_thread.GetSelectedFrame.return_value = mock_frame
        mock_frame.GetFunction.return_value = mock_function
        mock_function.GetName.return_value = "ut_lldb_check_point"
        
        # Mock the _get_global_variable method
        mock_var.GetSummary.return_value = '"test_checkpoint"'
        
        with patch.object(session, '_get_global_variable', return_value=mock_var):
            result = session._get_checkpoint_format_string()
            assert result == "test_checkpoint"
            session._get_global_variable.assert_called_once_with("lldb_current_checkpoint_name")
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_exec_with_cache(self, mock_lldb):
        """Test LLDBGdbSession.exec method with caching enabled."""
        mock_interpreter = MagicMock()
        session = LLDBGdbSession(mock_interpreter, use_cache=True)
        
        # Mock successful command execution
        mock_result = MagicMock()
        mock_result.Succeeded.return_value = True
        mock_result.GetOutput.return_value = "cached output"
        mock_interpreter.HandleCommand.return_value = None
        
        with patch('lldb_session.lldb.SBCommandReturnObject', return_value=mock_result):
            # First call should execute and cache
            result1 = session.exec("test command")
            assert result1 == "cached output"
            
            # Second call should return cached result
            result2 = session.exec("test command")
            assert result2 == "cached output"
            
            # Should only be called once due to caching
            assert mock_interpreter.HandleCommand.call_count == 1
    
    @patch('lldb_session.lldb')
    def test_lldb_gdb_session_exec_without_cache(self, mock_lldb):
        """Test LLDBGdbSession.exec method with caching disabled."""
        mock_interpreter = MagicMock()
        session = LLDBGdbSession(mock_interpreter, use_cache=False)
        
        # Mock successful command execution
        mock_result = MagicMock()
        mock_result.Succeeded.return_value = True
        mock_result.GetOutput.return_value = "fresh output"
        mock_interpreter.HandleCommand.return_value = None
        
        with patch('lldb_session.lldb.SBCommandReturnObject', return_value=mock_result):
            # First call
            result1 = session.exec("test command")
            assert result1 == "fresh output"
            
            # Second call should execute again (no caching)
            result2 = session.exec("test command")
            assert result2 == "fresh output"
            
            # Should be called twice since caching is disabled
            assert mock_interpreter.HandleCommand.call_count == 2

    @patch('lldb_session.lldb')
    @patch('lldb_session.time')
    def test_lldb_gdb_session_wait_until_exit_success(self, mock_time, mock_lldb):
        """Test LLDBGdbSession.wait_until_exit method with successful exit."""
        mock_interpreter = MagicMock()
        mock_target = MagicMock()
        mock_process = MagicMock()
        
        session = LLDBGdbSession(mock_interpreter)
        session.target = mock_target
        
        # Set up the mock constants
        mock_lldb.eStateExited = 7
        mock_lldb.eStateStopped = 5
        mock_lldb.eStateRunning = 3
        
        mock_target.GetProcess.return_value = mock_process
        mock_process.IsValid.return_value = True
        mock_process.GetState.return_value = 7  # Use the mocked constant value directly
        
        # Mock time to avoid actual delays
        mock_time.time.return_value = 0
        mock_time.sleep = MagicMock()
        
        # Should complete without raising an exception
        session.wait_until_exit()
        
        # Verify process.Continue() was called
        mock_process.Continue.assert_called_once()
    
    @patch('lldb_session.lldb')
    @patch('lldb_session.time')
    def test_lldb_gdb_session_wait_until_exit_timeout(self, mock_time, mock_lldb):
        """Test LLDBGdbSession.wait_until_exit method with timeout."""
        mock_interpreter = MagicMock()
        mock_target = MagicMock()
        mock_process = MagicMock()
        
        session = LLDBGdbSession(mock_interpreter)
        session.target = mock_target
        
        # Set up the mock constants
        mock_lldb.eStateExited = 7
        mock_lldb.eStateStopped = 5
        mock_lldb.eStateRunning = 3
        
        mock_target.GetProcess.return_value = mock_process
        mock_process.IsValid.return_value = True
        mock_process.GetState.return_value = 3  # Use the mocked constant value directly
        
        # Mock time to simulate timeout - allow loop to run at least once
        mock_time.time.side_effect = [0, 1.0, 6.0]  # Start at 0, then 1.0 (within timeout), then exceed TIMEOUT_FOR_EXIT (5.0)
        mock_time.sleep = MagicMock()
        
        with pytest.raises(RuntimeError) as exc_info:
            session.wait_until_exit()
        
        assert "Reached timeout without process exiting" in str(exc_info.value)
        assert "Process is at state: 3" in str(exc_info.value)
    
    @patch('lldb_session.lldb')
    @patch('lldb_session.time')
    def test_lldb_gdb_session_wait_until_exit_unexpected_checkpoint(self, mock_time, mock_lldb):
        """Test LLDBGdbSession.wait_until_exit when process stops at unexpected checkpoint."""
        mock_interpreter = MagicMock()
        mock_target = MagicMock()
        mock_process = MagicMock()
        
        session = LLDBGdbSession(mock_interpreter)
        session.target = mock_target
        
        # Set up the mock constants
        mock_lldb.eStateExited = 7
        mock_lldb.eStateStopped = 5
        mock_lldb.eStateRunning = 3
        
        mock_target.GetProcess.return_value = mock_process
        mock_process.IsValid.return_value = True
        mock_process.GetState.return_value = 5  # Use the mocked constant value directly
        
        # Mock time
        mock_time.time.return_value = 0
        mock_time.sleep = MagicMock()
        
        # Mock _get_checkpoint_format_string to return an unexpected checkpoint
        with patch.object(session, '_get_checkpoint_format_string', return_value="unexpected_checkpoint"):
            with pytest.raises(RuntimeError) as exc_info:
                session.wait_until_exit()
            
            assert "Process stopped at unexpected checkpoint 'unexpected_checkpoint' instead of exiting" in str(exc_info.value)


class TestBuildUtilitiesExtended:
    """Test additional build utilities functions."""
    
    @patch('pathlib.Path.glob')
    @patch('pathlib.Path.exists')
    def test_discover_unit_tests(self, mock_exists, mock_glob):
        """Test discover_unit_tests function."""
        from build_utils import discover_unit_tests
        
        # Mock the macros_testing directory exists
        mock_exists.return_value = True
        
        # Mock finding C files
        mock_c_files = [
            MagicMock(stem="test_memory_macros"),
            MagicMock(stem="test_vm_macros"),
            MagicMock(stem="test_proc_macros")
        ]
        mock_glob.return_value = mock_c_files
        
        result = discover_unit_tests()
        assert result == ["test_memory_macros", "test_vm_macros", "test_proc_macros"]
    
    @patch('build_utils.discover_unit_tests')
    @patch('build_utils.build_unit_test')
    def test_build_all_unit_tests_success(self, mock_build_unit_test, mock_discover):
        """Test build_all_unit_tests with all successful builds."""
        from build_utils import build_all_unit_tests
        
        mock_discover.return_value = ["test1", "test2"]
        mock_build_unit_test.return_value = None  # No exception means success
        
        result = build_all_unit_tests()
        assert result == {"test1": True, "test2": True}
        assert mock_build_unit_test.call_count == 2
    
    @patch('build_utils.discover_unit_tests')
    @patch('build_utils.build_unit_test')
    def test_build_all_unit_tests_partial_failure(self, mock_build_unit_test, mock_discover):
        """Test build_all_unit_tests with some failed builds."""
        from build_utils import build_all_unit_tests
        
        mock_discover.return_value = ["test1", "test2"]
        
        # First build succeeds, second fails
        def side_effect(exe_name):
            if exe_name == "test2":
                raise RuntimeError("Build failed")
        
        mock_build_unit_test.side_effect = side_effect
        
        result = build_all_unit_tests()
        assert result == {"test1": True, "test2": False}
