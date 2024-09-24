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

""" LLDB Scripted Process designed for unit-testing mock support. """

import unittest
import sys
import logging
from collections import namedtuple
from pathlib import Path

import lldb
import lldbmock.memorymock
from lldb.plugins.scripted_process import ScriptedProcess, ScriptedThread
from lldbtest.unittest import LLDBTextTestRunner, LLDBJSONTestRunner
from lldbtest.coverage import CoverageContext

# location of this script
SCRIPT_PATH = Path(__file__).parent

# Configure logging.
# This script is loaded first so we can share root logger with other files.

logging.root.setLevel(logging.INFO)
logging.basicConfig(level=logging.INFO)
lldb.test_logger = logging.getLogger("UnitTest")
lldb.test_logger.getChild("ScriptedProcess").info("Log initialized.")


class TestThread(ScriptedThread):
    """ Scripted thread that represents custom thread state. """


class TestProcess(ScriptedProcess):
    """ Scripted process that represents target's memory. """

    LOG = lldb.test_logger.getChild("ScriptedProcess")

    MockElem = namedtuple('MockElem', ['addr', 'mock'])

    def __init__(self, ctx: lldb.SBExecutionContext, args: lldb.SBStructuredData):
        super().__init__(ctx, args)

        self.verbose = args.GetValueForKey("verbose").GetBooleanValue()
        self.debug = args.GetValueForKey("debug").GetBooleanValue()
        self.json = args.GetValueForKey("json").GetStringValue(256)
        print(self.json)
        self._mocks = []

    #
    # Testing framework API
    #

    def add_mock(self, addr: int, mock: lldbmock.memorymock.BaseMock):
        # Do not allow overlaping mocks to keep logic simple.
        if any(me for me in self._mocks
               if me.addr <= addr < (me.addr + me.mock.size)):
            raise ValueError("Overlaping mock with")

        self._mocks.append(TestProcess.MockElem(addr, mock))

    def remove_mock(self, mock: lldbmock.memorymock.BaseMock):
        raise NotImplementedError("Mock removal not implemented yet")

    def reset_mocks(self):
        """ Remove all mocks. """
        self._mocks = []

    #
    # LLDB Scripted Process Implementation
    #

    def get_memory_region_containing_address(
        self,
        addr: int
    ) -> lldb.SBMemoryRegionInfo:
        # A generic answer should work in our case
        return lldb.SBMemoryRegionInfo()

    def read_memory_at_address(
        self,
        addr: int,
        size: int,
        error: lldb.SBError = lldb.SBError()
    ) -> lldb.SBData:
        """ Performs I/O read on top of set of mock structures.
            Undefined regions are set to 0.
        """
        data = lldb.SBData()
        rawdata = bytearray(size)

        # Avoid delegating reads back to SBTarget. That leads to infinite
        # recursion as SBTarget calls to read from SBProcess instance.

        # Overlay mocks on top of the I/O.
        for maddr, mock in (
            (me.addr, me.mock) for me
            in self._mocks):

            # check for overlap
            start_addr = max(addr, maddr)
            end_addr = min(addr + size, maddr + mock.size)

            if end_addr < start_addr:
                # no intersection of I/O and mock entry
                continue

            offs = start_addr - maddr # In the mock space
            boffs = start_addr - addr # In mbuffer space
            sz = end_addr - start_addr # size to read

            self.LOG.debug("overlap: %x +%d", offs, sz)
            self.LOG.debug("raw read %x +%d", addr, size)
            self.LOG.debug("final read %x +%d", start_addr - addr, sz)
            #self.LOG.debug("data: %s", mock.getData()[offs: offs + sz])

            # Merge mock data into I/O buffer.
            rawdata[boffs: boffs + sz] = mock.getData()[offs:offs+sz]

        data.SetDataWithOwnership(
            error,
            rawdata,
            lldb.eByteOrderLittle,
            8
        )

        return data

    def get_loaded_images(self) -> list:
        return self.loaded_images

    def get_process_id(self) -> int:
        return 0

    def is_alive(self) -> bool:
        return True

    def get_scripted_thread_plugin(self) -> str:
        return __class__.__module__ + '.' + TestThread.__name__


def run_unit_tests(debugger, _command, _exe_ctx, _result, _internal_dict):
    """ Runs standart Python unit tests inside LLDB. """

    # Obtain current plugin instance
    sp = debugger.GetSelectedTarget().GetProcess().GetScriptedImplementation()

    # Enable debugging
    if sp.debug:
        logging.root.setLevel(logging.DEBUG)
        logging.basicConfig(level=logging.DEBUG)

    log = logging.getLogger("ScriptedProcess")
    log.info("Running tests")
    log.info("Using path: %s", SCRIPT_PATH / "lldb_tests")
    tests = unittest.TestLoader().discover(SCRIPT_PATH / "lldb_tests")

    # Select runner class
    RunnerClass = LLDBJSONTestRunner if sp.json else LLDBTextTestRunner

    # Open output file if requested
    if sp.json:
        with open(f"{sp.json}-lldb.json", 'wt') as outfile:
            runner = RunnerClass(verbosity=2 if sp.verbose else 1, debug=sp.debug,
                                 stream=outfile)
            runner.run(tests)
    else:
        runner = RunnerClass(stream=sys.stderr, verbosity=2 if sp.verbose else 1,
                            debug=sp.debug)
        runner.run(tests)

def __lldb_init_module(_debugger, _internal_dict):
    """ LLDB entry point """

    # XNU has really bad import structure and it is easy to create circular
    # dependencies. Forcibly import XNU before tests are ran so the final
    # result is close to what imports from a dSYM would end up with.
    with CoverageContext():
        lldb.debugger.HandleCommand(
            f"command script import {SCRIPT_PATH / '../xnu.py'}")

    logging.getLogger("ScriptedProcess").info("Running LLDB module init.")
    lldb.debugger.HandleCommand(f"command script add "
                                f"-f {__name__}.{run_unit_tests.__name__}"
                                f" run-unit-tests")
