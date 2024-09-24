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

""" LLDB unit test runner

    This module implements main runner and result reporting.
"""

import json
import unittest
import unittest.case
import unittest.result

from enum import Enum
from collections import namedtuple
from traceback import TracebackException, format_exception
from textwrap import TextWrapper, indent

from lldbtest.testcase import LLDBTestCase
from lldbtest.coverage import cov_start, cov_stop

def _format_exc(exc):
    """ Format detailed exception for debugging purposes. """

    out_str = ""

    textwrap = TextWrapper(width=100, placeholder="...", max_lines=3)
    tbexc = TracebackException.from_exception(exc[1], limit=None,
                                              lookup_lines=True, capture_locals=True)

    for frame in tbexc.stack:
        out_str += f"File \"{frame.filename}\"  @{frame.lineno} in {frame.name}\n"
        out_str += "  Locals:\n"
        for name, value in frame.locals.items():
            variable = f"    {name} = "
            first = True
            for wline in textwrap.wrap(str(value)):
                if first:
                    out_str += variable + wline + "\n"
                    first = False
                else:
                    out_str += " " * (len(name) + 7) + wline + "\n"

        out_str += "  " + "-" * 100 + "\n"
        with open(frame.filename, "r", encoding='utf-8') as src:
            lines = src.readlines()
            startline = frame.lineno - 3 if frame.lineno > 2 else 0
            for lineno in range(startline, frame.lineno + 2):

                marker = '>' if (lineno + 1) == frame.lineno else ' '
                out_str += f"  {marker} {(lineno + 1):5}  {lines[lineno].rstrip()}\n"
        out_str += "  " + "-" * 100 + "\n"
        out_str += "\n"

    return out_str


#
# text based output
#


class LLDBTextTestResult(unittest.TextTestResult):
    """ Custom result instance that also records code coverage and other statistics. """

    def __init__(self, stream, descriptions, verbosity, debug = False):
        super().__init__(stream, descriptions, verbosity)

        self._debug_exception = debug

    def addError(self, test, err):

        if self._debug_exception:
            self.errors.append((test, _format_exc(err)))
        else:
            self.errors.append(
                (test, format_exception(err[0], err[1], err[2]))
            )

    def startTest(self, test) -> None:
        self._cov = cov_start()
        return super().startTest(test)

    def stopTest(self, test) -> None:
        cov_stop(self._cov)
        return super().stopTest(test)


class LLDBTextTestRunner(unittest.TextTestRunner):
    """ Test runner designed to run unit tests inside LLDB instance. """

    def __init__(self, stream = None, descriptions = True, verbosity = 1,
                 failfast = False, buffer = False, resultclass = None, warnings = None,
                 *, tb_locals = False, debug = False) -> None:
        super().__init__(stream, descriptions, verbosity, failfast, buffer, resultclass,
                         warnings, tb_locals=tb_locals)
        self._debug = debug

    def _makeResult(self) -> 'LLDBTextTestResult':
        return LLDBTextTestResult(self.stream, self.descriptions, self.verbosity,
                                  self._debug)

    def _printTestDescription(self, state, test):
        """ display test details """

        self.stream.writeln()

        if isinstance(test, LLDBTestCase):
            self.stream.writeln(f' {state}: {test.id()} ({test.COMPONENT})')
        else:
            self.stream.writeln(f' {state}: {test}')
            self.stream.writeln()
            return

        self.stream.writeln()
        self.stream.writeln(' Description:')

        if doc := test.getDescription():
            self.stream.writeln()
            self.stream.writelines(indent(doc, "    "))
            self.stream.writeln()

        self.stream.writeln()

    def printFailureDetails(self, result: LLDBTextTestResult) -> None:
        """ display failures """

        self.stream.writeln()

        for test, failure in result.failures:
            self.stream.writeln()
            self.stream.writeln('=' * 100)
            self._printTestDescription("FAILED", test)
            self.stream.writeln('-' * 100)
            self.stream.writeln()
            self.stream.writelines(failure)
            self.stream.writeln('=' * 100)

        self.stream.writeln()

    def printErrorDetails(self, result):
        """ display error details """

        self.stream.writeln()

        for test, error in result.errors:
            self.stream.writeln()
            self.stream.writeln('=' * 100)
            self._printTestDescription("ERROR", test)
            self.stream.writeln('-' * 100)
            self.stream.writeln()
            self.stream.writelines(error)
            self.stream.writeln('=' * 100)

        self.stream.writeln()

    def printOveralResults(self, result):
        """ Print overal summary of results. """

        self.stream.writeln()
        self.stream.writeln('-' * 100)
        self.stream.writeln(f'  Tests total:   {result.testsRun:5}')
        self.stream.writeln(f'  Tests failed:  {len(result.failures):5}')
        self.stream.writeln(f'  Tests skipped: {len(result.skipped):5}')
        self.stream.writeln(f'  Test errors:   {len(result.errors):5}')
        self.stream.writeln('-' * 100)

    def printSkippedDetails(self, result):
        """ Print summary of skipped tests and reasons. """

        self.stream.writeln()
        self.stream.writeln('=' * 100)
        for test, reason in result.skipped:
            self.stream.writeln(f' SKIPPED {test.id()} - {reason}')
        self.stream.writeln('=' * 100)

    def run(self, test):
        result = self._makeResult()

        # Run a test case / test suite
        result.startTestRun()
        try:
            test(result)
        finally:
            result.stopTestRun()

        # Display failures
        if result.failures:
            self.printFailureDetails(result)

        # Display exceptions
        if result.errors:
            self.printErrorDetails(result)

        # Display skipped tests
        if result.skipped:
            self.printSkippedDetails(result)

        # Print summary
        self.printOveralResults(result)

        return result


#
# JSON file based output
#


class LLDBTestResult(unittest.TestResult):
    """ Holds results of all tests encode as Result tuple for later processing. """

    # Tuple holding result of every test ran.
    Result = namedtuple('Result', ['test', 'result', 'detail'])

    # Enum holding result type
    class ResultCode(str, Enum):
        PASS = 0
        SKIP = 1
        ERROR = 2

    def __init__(self, stream = None, descriptions = None, verbosity = None):
        super().__init__(stream, descriptions, verbosity)

        self._cov = None
        self.tests = []

    def addError(self, test, err):

        exc = _format_exc(err)
        self.errors.append((test, _format_exc(err)))

        self.tests.append(LLDBTestResult.Result(
            test, LLDBTestResult.ResultCode.ERROR, exc
        ))

    def addExpectedFailure(self, test, err):
        self.tests.append(LLDBTestResult.Result(
            test, LLDBTestResult.ResultCode.ERROR, err
        ))
        return super().addExpectedFailure(test, err)

    def addSkip(self, test, reason):
        self.tests.append(LLDBTestResult.Result(
            test, LLDBTestResult.ResultCode.SKIP, reason
        ))
        return super().addSkip(test, reason)

    def addFailure(self, test, err):
        # This path is most of the time taken by failed assertions. There is no
        # point in providing detailed backtraces for assert failures.
        exc = format_exception(err[0], err[1], err[2])

        self.tests.append(LLDBTestResult.Result(
            test, LLDBTestResult.ResultCode.ERROR, exc
        ))
        return super().addFailure(test, err)

    def addSuccess(self, test):
        self.tests.append(LLDBTestResult.Result(
             test, LLDBTestResult.ResultCode.PASS, None
             ))
        return super().addSuccess(test)

    def addUnexpectedSuccess(self, test):
        self.tests.append(LLDBTestResult.Result(
            test, LLDBTestResult.ResultCode.PASS, None
        ))
        return super().addUnexpectedSuccess(test)

    def startTest(self, test) -> None:
        self._cov = cov_start()
        return super().startTest(test)

    def stopTest(self, test) -> None:
        cov_stop(self._cov)
        return super().stopTest(test)


class LLDBJSONTestRunner(unittest.TextTestRunner):
    """ Produces JSON report of the test run. """

    def __init__(self, stream = None, descriptions = True, verbosity = 1,
                 failfast = False, buffer = False, resultclass = None, warnings = None,
                 *, tb_locals = False, debug = False) -> None:
        super().__init__(stream, descriptions, verbosity, failfast, buffer, resultclass,
                         warnings, tb_locals=tb_locals)
        self._debug = debug

    def _makeResult(self) -> 'LLDBTextTestResult':
        return LLDBTestResult(self.stream, self.descriptions, self.verbosity)

    def run(self, test):
        result = self._makeResult()

        # Run a test case / test suite
        result.startTestRun()
        try:
            test(result)
        finally:
            result.stopTestRun()

        # Write JSON result file
        test_results = []

        for res in result.tests:
            if isinstance(res.test, LLDBTestCase):
                test_results.append({
                    "id": res.test.id(),
                    "desc": res.test.getDescription(),
                    "result": res.result,
                    "detail": res.detail
                })
            else:
                test_results.append({
                    "id": str(res.test),
                    "desc": "",
                    "result": res.result,
                    "detail": res.detail
                })

        json.dump(test_results, self.stream)

        return result
