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

""" Test case base class for tests running inside LLDB """

import unittest.result
import sys
import re
from unittest import TestCase

import lldb
from lldbmock.memorymock import MockFactory, BaseMock


class LLDBTestCase(TestCase):
    """ LLDB unit test running inside LLDB instance.

        This class ensures that a test will get an instance of the debugger attached
        to a scripted process mock. Test can interact with LLDB directly through
        SBAPIs available.
    """

    COMPONENT = "xnu | debugging"

    def run(self, result: unittest.TestResult) -> unittest.TestResult:
        """ Run a test and slufh LLDB I/O caches. """

        self.invalidate_cache()
        return super().run(result)

    def __init__(self, methodName):
        """ Initializes test case and logging. """

        super().__init__(methodName)
        self.log = lldb.test_logger.getChild(self.__class__.__name__)

    @property
    def debugger(self):
        """ Returns SBDebugger instance used during test execution. """

        return lldb.debugger

    @property
    def process(self):
        """ Returns SBPRocess instance used during test execution. """

        return self.target.GetProcess()

    @property
    def spplugin(self):
        """ Returns Scripted Process plugin used during execution. """

        return self.process.GetScriptedImplementation()

    @property
    def target(self):
        """ Return target used during test execution. """

        return lldb.debugger.GetSelectedTarget()

    def create_mock(self, sbtype: str, addr: int = None):
        """ Returns instance of mock object matching sbtype. """

        self.log.debug("Creating mock from %s", sbtype)
        mock = MockFactory.createFromType(sbtype)

        if addr is not None:
            self.add_mock(addr, mock)

        return mock

    def add_mock(self, addr: int, mock: BaseMock):
        """ Insert mock instance to the target. """

        self.spplugin.add_mock(addr, mock)

    def run_command(self, command: str) -> lldb.SBCommandReturnObject:
        """ Runs LLDB command and returns result. """

        res = lldb.SBCommandReturnObject()
        self.debugger.GetCommandInterpreter().HandleCommand(command, res)
        return res

    def invalidate_cache(self):
        """ Invalidates cached I/O by simulating proces start/stop. """

        self.process.ForceScriptedState(lldb.eStateRunning)
        self.process.ForceScriptedState(lldb.eStateStopped)

    def reset_mocks(self):
        """ Remove all registered mocks. """

        self.spplugin.reset_mocks()

    # Helpers for skipIf() has to be static methods because they are called from
    # decorator before a test class is instantiated.

    @staticmethod
    def variant():
        """ Return variant of kernel being loaded. """

        # Version string is a static variable in the kernel image.
        # Use SBTarget to read it's memory as that's not mocked away
        # by scripted process.
        target = lldb.debugger.GetSelectedTarget()
        version = target.FindGlobalVariables('version', 1).GetValueAtIndex(0)
        err = lldb.SBError()
        addr = target.ResolveLoadAddress(version.AddressOf().GetLoadAddress())

        # Filter first world from a triplet VARIANT_PLATFORM_SOC
        verstr = target.ReadMemory(addr, version.GetByteSize(), err)
        kerntgt = re.search("^.*/(.*)$", verstr.decode())[1]
        return kerntgt.split('_')[0]

    @staticmethod
    def arch():
        """ Return current architecture. """

        return lldb.debugger.GetSelectedTarget().triple.split('-', 1)[0]

    @staticmethod
    def kernel():
        """ Return name of XNU module in current target. """

        target = lldb.debugger.GetSelectedTarget()
        kernel = (
            m.file.basename
            for m in target.module_iter()
            if m.file.basename.startswith(('kernel', 'mach'))
        )
        return next(kernel, None)


    def getDescription(self):
        """ Returns unindented doc string of currently tested method. """

        # Convert tabs to spaces (following the normal Python rules)
        # and split into a list of lines:
        lines = self._testMethodDoc.expandtabs().splitlines()

        # Determine minimum indentation (first line doesn't count):
        indent = sys.maxsize
        for line in lines[1:]:
            stripped = line.lstrip()
            if stripped:
                indent = min(indent, len(line) - len(stripped))

        # Remove indentation (first line is special):
        trimmed = [lines[0].strip()]
        if indent < sys.maxsize:
            for line in lines[1:]:
                trimmed.append(line[indent:].rstrip())

        # Strip off trailing and leading blank lines:
        while trimmed and not trimmed[-1]:
            trimmed.pop()
        while trimmed and not trimmed[0]:
            trimmed.pop(0)

        # Return a single string:
        return '\n'.join(trimmed)

    @classmethod
    def setUpClass(cls) -> None:
        """ All mocks are reset per class instance fixture. """

        lldb.debugger.GetSelectedTarget().GetProcess() \
            .GetScriptedImplementation().reset_mocks()
        return super().setUpClass()
