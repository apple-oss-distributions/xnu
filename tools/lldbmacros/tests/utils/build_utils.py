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

"""Build utilities for LLDB macro tests."""
import subprocess
import os
from constants import XNU_ROOT, DEFAULT_SDKROOT, UNIT_TESTS_DIR, MACROS_TESTING_DIR

def build_unit_test(exe_name: str):
    """Build a unit test executable using make.
    
    Args:
        exe_name: Name of the executable to build (e.g., "test_memory_macros")
    
    Raises:
        RuntimeError: If the build fails
    """
    # Change to XNU root directory for the build
    original_cwd = os.getcwd()
    
    try:
        os.chdir(XNU_ROOT)
        
        # Construct the full target name with macros_testing prefix
        target_name = f"{MACROS_TESTING_DIR}/{exe_name}"
        
        # Run the make command
        cmd = [
            "make",
            "-C", UNIT_TESTS_DIR,
            f"SDKROOT={DEFAULT_SDKROOT}",
            target_name
        ]
        
        print(f"Building unit test: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode != 0:
            error_msg = f"Build failed for {exe_name}\n"
            error_msg += f"Command: {' '.join(cmd)}\n"
            error_msg += f"Return code: {result.returncode}\n"
            error_msg += f"STDOUT: {result.stdout}\n"
            error_msg += f"STDERR: {result.stderr}"
            raise RuntimeError(error_msg)
        
        print(f"Successfully built {exe_name}")
        if result.stdout:
            print(f"Build output: {result.stdout}")
            
    finally:
        # Always restore the original working directory
        os.chdir(original_cwd)

def discover_unit_tests():
    """Discover all unit test C files in the macros_testing directory.
    
    Returns:
        list: List of executable names (without .c extension) that can be built
    """
    macros_testing_path = XNU_ROOT / "tests" / "unit" / "macros_testing"
    
    if not macros_testing_path.exists():
        print(f"Warning: macros_testing directory not found at {macros_testing_path}")
        return []
    
    # Find all .c files in the macros_testing directory
    c_files = list(macros_testing_path.glob("*.c"))
    
    # Extract executable names (remove .c extension)
    exe_names = [c_file.stem for c_file in c_files]
    
    print(f"Discovered {len(exe_names)} unit test(s): {exe_names}")
    return exe_names

def build_all_unit_tests():
    """Build all discovered unit test executables.
    
    Returns:
        dict: Dictionary with exe_name as key and success status as value
    """
    exe_names = discover_unit_tests()
    
    if not exe_names:
        print("No unit tests found to build")
        return {}
    
    print(f"Building {len(exe_names)} unit test executable(s)...")
    
    results = {}
    failed_builds = []
    
    for exe_name in exe_names:
        try:
            print(f"\n--- Building {exe_name} ---")
            build_unit_test(exe_name)
            results[exe_name] = True
            print(f"✓ Successfully built {exe_name}")
        except RuntimeError as e:
            results[exe_name] = False
            failed_builds.append(exe_name)
            print(f"✗ Failed to build {exe_name}: {e}")
    
    # Summary
    successful_builds = [name for name, success in results.items() if success]
    
    print("\n=== Build Summary ===")
    print(f"Total: {len(exe_names)}")
    print(f"Successful: {len(successful_builds)}")
    print(f"Failed: {len(failed_builds)}")
    
    if successful_builds:
        print(f"✓ Built: {', '.join(successful_builds)}")
    
    if failed_builds:
        print(f"✗ Failed: {', '.join(failed_builds)}")
        # Don't raise an exception here - let tests run with available executables
        print("Warning: Some builds failed, but continuing with available executables")
    
    return results
