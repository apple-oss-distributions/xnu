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

"""Pytest configuration and fixtures for LLDB macro tests."""

import sys
import os

# Add utils directory to path so we can import build utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'utils'))

from lldb_session import set_skip_build


def pytest_addoption(parser):
    """Add custom command-line options to pytest."""
    parser.addoption(
        "--skip-build",
        action="store_true",
        default=False,
        help="Skip building unit test executables (use existing ones)"
    )


def pytest_configure(config):
    """Configure pytest session based on command-line options."""
    # Store the skip-build flag in order for tests to use it
    skip = config.getoption("--skip-build")
    set_skip_build(skip)

    if not skip:
        print("Use --skip-build flag to skip all building and use existing executables")
