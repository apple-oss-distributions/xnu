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

# pylint: disable=invalid-name
# pylint: disable=protected-access

""" Test process.py """

import unittest
from lldbmock.utils import lookup_type
from lldbmock.valuemock import ValueMock

import process as tst_process
import utils as tst_utils


class ProcessTest(unittest.TestCase):
    """ Tests for process.py module """

    def test_GetProcPid(self):
        """ Test a pid gets returned. """

        proc = ValueMock.createFromType('proc')
        proc.p_pid = 12345

        self.assertEqual(tst_process.GetProcPID(proc), 12345)
        self.assertEqual(tst_process.GetProcPID(None), -1)

    def test_GetNameShort(self):
        """ Test fallback to short name. """

        proc = ValueMock.createFromType('proc')
        proc.p_name = ""
        proc.p_comm = "short-proc"

        self.assertEqual(tst_process.GetProcName(proc), "short-proc")

    def test_GetNameLong(self):
        """ Test that long name is preferred. """

        proc = ValueMock.createFromType('proc')
        proc.p_name = "long-proc"
        proc.p_comm = "short-proc"

        self.assertEqual(tst_process.GetProcName(proc), "long-proc")

    def test_GetNameInvalid(self):
        """ Test that invalid proc returns default name. """

        self.assertEqual(
            tst_process.GetProcName(None),
            tst_process.NO_PROC_NAME
        )

    def test_ASTValuesInSync(self):
        """ Test that thread states cover all values defined in kernel. """

        # Compare all values with AST chars dictionary.
        macro = tst_process._AST_CHARS.keys()

        # Add rest of values from the enum in kernel.
        enum = lookup_type('ast_t')
        self.assertTrue(enum.IsValid())

        kernel = [
            k.GetValueAsUnsigned()
            for k in enum.get_enum_members_array()
        ]

        # Assert that both sides handle identical set of flags.
        self.assertSetEqual(set(macro), set(kernel),
                            "thread state chars mismatch")

    def test_GetAstSummary(self):
        """ Test AST string genration. """

        ast = tst_utils.GetEnumValue('ast_t', 'AST_DTRACE')
        ast |= tst_utils.GetEnumValue('ast_t', 'AST_TELEMETRY_KERNEL')

        # Check valid AST
        self.assertEqual(tst_process.GetASTSummary(ast), 'TD')

        # Check that we never touch unsupported bits in an invalid value
        ast = 0xffffffff
        aststr = ''.join(char for _, char in tst_process._AST_CHARS.items())

        self.assertEqual(tst_process.GetASTSummary(ast), aststr)
