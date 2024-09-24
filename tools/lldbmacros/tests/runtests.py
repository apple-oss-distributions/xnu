#!/usr/bin/env python3

##
# Copyright (c) 2023 Apple Inc. All rights reserved.
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

"""
LLDB unit-test runner.

Discovers all unit-test that require LLDB instance and runs them from within
LLDB testing environment.
"""
import atexit
import argparse
import unittest
from unittest.mock import patch, MagicMock
import sys
import json
from pathlib import Path

from lldbtest.coverage import cov_html
from lldbtest.unittest import LLDBTextTestRunner, LLDBJSONTestRunner

#
# Handle arguments
#
parser = argparse.ArgumentParser(
    prog='runtests',
    description='Runs lldb macro unit-tests against selected kernel'
)
parser.add_argument('kernel')
parser.add_argument('-v', '--verbose', action='store_true')
parser.add_argument('-d', '--debug', action='store_true')
parser.add_argument('-c', '--coverage')
parser.add_argument('-s', '--standalone', action='store_true')
parser.add_argument('-j', '--json')

args = parser.parse_args()

# To avoid duplicates call this each time a script exists.
def exit_handler():
    if args.coverage:
        print('writing out coverage report ...')
        cov_html(directory=args.coverage)

    print('done.')

atexit.register(exit_handler)

SCRIPT_PATH = Path(__file__).parent

# Select test runner class
RunnerClass = LLDBJSONTestRunner if args.json else LLDBTextTestRunner

#
# A unit-test discovery requires to import tests as a module. This in turns
# imports XNU which re-exports all dSYM modules. This results in failure to
# discover tests.
#
# For now mock away lldb and lldb_wrap which are not available for standalone
# unit tests.
#
print("Running standalone unit tests\n")

with patch.dict('sys.modules', { 'lldb': MagicMock(), 'core.lldbwrap': MagicMock() }):

    # Discover unit-tests
    tests = unittest.TestLoader().discover(SCRIPT_PATH / "standalone_tests")

    # Open output file if requested
    if args.json:
        with open(f"{args.json}-standalone.json", 'wt') as outfile:
            runner = RunnerClass(verbosity=2 if args.verbose else 1, debug=args.debug,
                                 stream=outfile)
            runner.run(tests)
    else:
        runner = RunnerClass(verbosity=2 if args.verbose else 1, debug=args.debug)
        runner.run(tests)

if args.standalone:
    sys.exit()

#
# Discover and run LLDB tests
#
print('Running LLDB unit tests\n')

try:
    import lldb
except ImportError:
    print("LLDB not available skipping tests.")
    sys.exit()

# Create Debugger instance
debugger = lldb.SBDebugger.Create()

# Created ScriptedProcess target for selected kernel binary
error = lldb.SBError()
target = debugger.CreateTargetWithFileAndArch(args.kernel, None)

# Load scripts
ret = lldb.SBCommandReturnObject()
ci = debugger.GetCommandInterpreter()

print('Loading scripted process plugin')
ci.HandleCommand(f'command script import {SCRIPT_PATH / "lldb_test_process.py"}',
    ret)

#
# Create Scripted Process for testing.
# Python running this script and Python running inside LLDB may not match.
# It is prefered to not shared anything across this boundary.
#
structured_data = lldb.SBStructuredData()
structured_data.SetFromJSON(json.dumps({
    "verbose": args.verbose,
    "debug": args.debug,
    "json": args.json
}))

launch_info = lldb.SBLaunchInfo(None)
launch_info.SetScriptedProcessDictionary(structured_data)
launch_info.SetLaunchFlags(lldb.eLaunchFlagStopAtEntry)
launch_info.SetWorkingDirectory(".")
launch_info.SetProcessPluginName("ScriptedProcess")
launch_info.SetScriptedProcessClassName('lldb_test_process.TestProcess')

process = target.Launch(launch_info, error)
if error.fail:
    print(error.description)
if not error.Success():
    sys.exit()

ci.HandleCommand('run-unit-tests', ret)
