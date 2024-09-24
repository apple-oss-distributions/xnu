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

from abc import ABCMeta

import lldb


def visit_type(sbtype: lldb.SBType, offs = 0):
    """ Recursively visit all members of a SBType instance. """

    # Yield simple types back
    if sbtype.GetNumberOfFields() == 0:
        yield (sbtype, 0)

    for t in sbtype.get_members_array():
        if t.GetType().IsAnonymousType():
            yield from visit_type(t.GetType(), offs + t.GetOffsetInBytes())
        else:
            yield (t, offs + t.GetOffsetInBytes())

#
# For now this is a very simple type lookup which does not take into
# account any complex scenarios (multiple different definitions or
# symbol scope).
#
def lookup_type(sbtype):
    """ Look up SBType by name. """

    # Pass through if we have type already.
    if isinstance(sbtype, lldb.SBType):
        return sbtype

    # Lookup SBType by name.
    rettype = lldb.debugger.GetSelectedTarget().FindFirstType(sbtype)
    if not rettype.IsValid():
        raise AttributeError(f"No such type found ({sbtype})")

    return rettype


class Singleton(ABCMeta):
    """ Meta class for creation of singleton instances. """

    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
