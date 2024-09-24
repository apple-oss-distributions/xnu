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

""" Value class mock

    The main purpose of this mock is to allow easy mocking of value class
    instance inside LLDB macros. A mock is constructed from a SBType instance
    and replicates all of its members as attributes. The final result is almost
    identical to value class and user can access members with:

        mock.member.sub_member = ...

    There is no handling of unions/bitfields so developer has to carefuly fill
    the members.

    Given that a mock is replicating SBType from real kernel it is possible to
    use it to check whether an attribute is present or not in the final binary.

    For example to catch problems where a member is compiled out on RELEASE
    kernel.
"""

import unittest.mock
from typing import Union
from lldbmock.utils import visit_type, lookup_type
import lldb


class ValueMock(unittest.mock.MagicMock):
    """ Creates mock of a C structure (not extensible) based on binary dSYM. """

    @staticmethod
    def _createArray(mocktype):

        count = mocktype.GetByteSize() // mocktype.GetArrayElementType().GetByteSize()

        return [
            ValueMock.createFromType(mocktype.GetArrayElementType())
            for _ in range(count)
        ]

    @staticmethod
    def createFromType(mocktype: Union[lldb.SBType, str]) -> 'ValueMock':
        """ Creates ValueMock for selected type.

            A type is specified either as string or SBType.
        """
        sbtype = lookup_type(mocktype)
        type_class = sbtype.GetTypeClass()

        # Handle arrays
        if type_class == lldb.eTypeClassArray:
            return ValueMock._createArray(sbtype)

        # Convert SBType members to mock specification.
        instmock = ValueMock(spec_set = [
            t.GetName() for t, _
            in visit_type(sbtype)
            if isinstance(t, lldb.SBTypeMember)
        ])

        # Recursively construct sub-mocks for compound type members.
        for member, _ in visit_type(sbtype):
            if isinstance(member, lldb.SBTypeMember) and \
                member.GetType().GetNumberOfFields() > 0:

                nest = ValueMock.createFromType(member.GetType())
                setattr(instmock, member.GetName(), nest)

        return instmock
