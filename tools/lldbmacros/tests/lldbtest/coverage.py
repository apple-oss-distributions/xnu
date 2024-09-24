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

""" Source code coverage report

    This module tracks source code coverage if requried modules are installed.
    Coverage tracking is disabled when the `coverage` library is missing.
"""

import contextlib

try:
    import coverage
    COVERAGE_ENABLED = True
except ImportError:
    COVERAGE_ENABLED = False


def cov_start():
    """ Start coverage tracking. """

    if not COVERAGE_ENABLED:
        return None

    cov = coverage.Coverage(auto_data=True)
    cov.load()
    cov.start()

    return cov

def cov_stop(cov):
    """ Stop coverage tracking. """

    if not cov:
        return

    cov.stop()
    cov.save()

def cov_html(directory):
    """ Produce HRML report from current coverage data. """

    if not COVERAGE_ENABLED:
        print("Coverage module not installed.")
        return

    cov = coverage.Coverage(auto_data=True)
    cov.load()
    cov.html_report(directory=directory,
                    include=[
                        '*/lldbmacros/*'
                    ],
                    omit=[
                        '*/lldbmacros/tests/*'
                    ])


class CoverageContext(contextlib.AbstractContextManager):
    """ Coverage tracking context manager. """

    def __init__(self):
        self._cov = None

    def __enter__(self):
        self._cov = cov_start()
        return super().__enter__()

    def __exit__(self, __exc_type, __exc_value, __traceback):
        cov_stop(self._cov)
        return super().__exit__(__exc_type, __exc_value, __traceback)
