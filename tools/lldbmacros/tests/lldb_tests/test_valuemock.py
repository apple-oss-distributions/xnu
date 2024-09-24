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

""" Tests for ValueMock class

    Validates implementation of ValueMock mock class.
"""

import unittest
from lldbmock.valuemock import ValueMock
from lldbmock.utils import lookup_type


class MockTest(unittest.TestCase):
    """ Tests that mocking subsystem is working as expected. """

    def test_mockValidMember(self):
        """ Ensure that valid member access works. """

        proc = ValueMock.createFromType('proc')

        proc.p_pid = 5
        self.assertEqual(proc.p_pid, 5)

    def test_mockInvalidMember(self):
        """ Ensure that invalid member access fails. """

        proc = ValueMock.createFromType('proc')

        with self.assertRaises(AttributeError):
            proc.foobar = 1

    def test_mockAnonUnion(self):
        """ Ensure that anon members are propagated to top level."""

        proc = ValueMock.createFromType('proc')
        self.assertTrue(hasattr(proc, 'p_pid'))

    def test_mockNestedInvalid(self):
        """ Ensure that all sub-members are also speced mocks. """

        proc = ValueMock.createFromType('proc')

        with self.assertRaises(AttributeError):
            proc.p_list.foobar = 1

    def test_mockNestedValid(self):
        """ Ensure that all sub-members are initialized mocks. """

        proc = ValueMock.createFromType('proc')
        proc.p_list.le_next = 5
        proc.p_list.le_prev = 5
        self.assertTrue(proc.p_list.le_next, 5)

    def test_mockSimpleType(self):
        """ Ensure that mock works for non-coumpound types. """

        value = ValueMock.createFromType('uint32_t')

        # It is not possible to set a member
        with self.assertRaises(AttributeError):
            value.foo_member = 5

        # It is possible to set a value
        value = 5
        self.assertEqual(value, 5)

    def test_mockArray(self):
        """ Ensure that array can use index operator. """

        arrtype = lookup_type('proc').GetArrayType(11)
        procarr = ValueMock.createFromType(arrtype)

        procarr[10].p_comm = "Hello world"
        procarr[0].p_comm = "testproc"
        procarr[3].p_comm = "slice"
        procarr[4].p_comm = "slice"
        procarr[5].p_comm = "slice"

        self.assertEqual(procarr[10].p_comm, "Hello world")
        self.assertNotEqual(procarr[0].p_comm, procarr[10].p_comm)

        with self.assertRaises(AttributeError):
            procarr[5].foobar = 5

        self.assertSetEqual(set(a.p_comm for a in procarr[3:6]), {'slice'})
