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

""" Mocking framework for LLDB scripted process target.

    The goal of this module is to provide a mock object that behaves like
    original SBType in target but serializes its properties into memory.

    That allows injection of artificial type instances into testing target.
"""

from abc import ABC, abstractmethod
import typing
import lldb
import io
from lldbmock.utils import lookup_type, Singleton


#
# Data serializers
#
# A goal of a serializer is to convert between Python's native type and byte
# array used internally by mocking layer. This allows users to more easily operate
# on mock properties.
#
# For example:
#
#      mock.numeric_property = 0x12345
#
# The value above ends up encoded as little endian at correct offset in the
# mocked type memory.
#


class Serializer(ABC):
    """ Value serializer. """

    @abstractmethod
    def accepts(self, value: typing.Any) -> bool:
        """ Checks that value instance is supported. """

    @abstractmethod
    def serialize(self, value: typing.Any, size: int) -> bytes:
        """ Serializes value to raw bytes"""

    @abstractmethod
    def deserialize(self, data: bytes, offs: int, size: int) -> typing.Any:
        """ Deserialize value from raw bytes. """

    @abstractmethod
    def default(self):
        """ Return default value for a property. """

    @staticmethod
    def createSerializerForType(sbtype: lldb.SBType) -> 'Serializer':
        """ Construct serializer for given SBType. """

        flags = sbtype.GetTypeFlags()

        if (flags & (lldb.eTypeIsInteger | lldb.eTypeIsPointer)) != 0:
            return NumericSerializer()

        # Default: No serializer enforces bytes instances as input.
        return NoSerializer()


class NoSerializer(Serializer, metaclass=Singleton):
    """ No transformation, only enforces bytes as input. """

    def default(self):
        return b''

    def accepts(self, value: typing.Any) -> bool:
        if isinstance(value, bytes) or isinstance(value, bytearray):
            return True

        return False

    def serialize(self, value: typing.Any, size: int) -> bytes:
        return value[:size]

    def deserialize(self, data: bytes, offs: int, size: int) -> typing.Any:
        return data[offs : offs + size]


class NumericSerializer(Serializer, metaclass=Singleton):
    """ Serializes python's numeric (integral) types to bytes. """

    def default(self):
        return 0

    def accepts(self, value: typing.Any) -> bool:
        if isinstance(value, int):
            return True

        return False

    def serialize(self, value: typing.Any, size: int) -> bytes:
        return value.to_bytes(length=size, byteorder='little')

    def deserialize(self, data: bytes, offs: int, size: int) -> typing.Any:
        return int.from_bytes(data[offs: offs + size], byteorder='little')


#
# Mock class properties
#
# Mock does not create attributes on an instance class. Instead a MockProperty
# is created on a base class that contains enough metadata to find a value of
# a property in class instance's buffer.
#
# To achieve this a MockProperty implements Python's descriptor protocol and
# overrides __get__/__set__ methods. Every access results in data being
# serialized or deserialized from the instance's buffer.
#
#        +-----------------+                     +-----------------+
#        | Mock base class |                     | Mock instance   |
#        +-----------------+                     +-----------------+
#        |                 |                     | Buffer          |
#        |                 |                     |                 |
#        |                 |<--------------------|                 |
#        |                 |                     |                 |
#        +-----------------+                     |    +-------+    |
#        | MockProperty    |                     |    +-------+    |
#        +-----------------+                     |        |        |
#        |        |        |                     |        |        |
#        +--------|--------+                     +--------|--------+
#                 +---------------------------------------+
#
#
# It is allowed to create overlaping properties. This helps in solving support
# for union types.

class MockProperty:
    """ Serializable property on the mock object.

        A property maintains size/offset based on DWARF so it knows where to
        serialize its own data inside an owner's buffer.
    """

    def __init__(self, offs, sz, serializer=NoSerializer()):
        """ Create property with given ofset, size and serializer. """

        self._offs = offs
        self._sz = sz
        self._attrname = None
        self.serializer = serializer

    def __set__(self, instance, value):
        """ Updates shadow attribute on target's instance. """

        # Enforce that value is serializable.
        if not self.serializer.accepts(value):
            raise AttributeError("Unsupported value for this property")

        # Serialize value to instance's buffer
        data = self.serializer.serialize(value, self._sz)
        instance._buf[self._offs: self._offs + min(self._sz, len(data))] = data

    def __get__(self, instance, owner = None):
        """ Retruns value from the shadow attribute on an instance. """

        return self.serializer.deserialize(instance._buf, self._offs, self._sz)

    def __delete__(self, instance):
        """ Deletes property. """

        # It is not possible to delete a type's member dynamically.
        # The property mirros that behavior.
        raise AttributeError("MockProperty instances can't be deleted.")

    def __set_name__(self, owner, name):
        """ Registers owning class property name. """

        self._attrname = f'_{name}'

    def deserialize(self, data: bytes) -> typing.Any:
        """ De-serializes value of a property from data. """

        return self.serializer.deserialize(data, self._offs, self._sz)


class BitArray:
    """ Simple wrapper around bytearray that provites bit access.

        Note: The implementation is limited to mock requirements.
              Not suitable for general purpose use.
    """

    def __init__(self, bytes):
        self._buf = bytes

    def __getbit(self, idx):
        byte = self._buf[idx // 8]
        return byte & (1 << (idx % 8)) != 0

    def __setbit(self, idx, value):
        if value:
            self._buf[idx // 8] |= (1 << idx % 8)
        else:
            self._buf[idx // 8] &= ~(1 << idx % 8)

    def __getitem__(self, key):
        if isinstance(key, slice):
            return [self[ii] for ii in range(*key.indices(len(self)))]

        return self.__getbit(key)

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            raise NotImplementedError("Not donbe yet")

        self.__setbit(key, value)

    def __len__(self):
        return len(self._buf) * 8

    def __str__(self):
        s = "b"
        for byte in self._buf:
            for bit in range(0, 7):
                s += "1" if byte & (1 << bit) else "0"

        return s


class BitfieldProperty(MockProperty):
    """ Similar to MockProperty but all operations are in bits.

        This type of property is used exclusively to implement bitfields.
    """

    def __init__(self, offs, sz, serializer=NoSerializer()):
        # Enforce NumericSerializer for bitfields.
        super().__init__(offs, sz, NumericSerializer())

        self._bsz = (sz + 8) >> 3

    def __set__(self, instance, value):
        """ Updates shadow attribute on target's instance. """

        # Enforce that value is serializable.
        if not self.serializer.accepts(value):
            raise AttributeError("Unsupported value for this property")

        # Serialize value to instance's buffer
        data = self.serializer.serialize(value, self._bsz)
        barr = BitArray(instance._buf)

        offs = 0
        for b in data:
            for i in range(0, 8):
                barr[self._offs + offs] = b & (1 << i) != 0

                if offs == self._sz - 1:
                    break

                offs += 1

    def __get__(self, instance, owner = None):
        """ Retruns value from the shadow attribute on an instance. """

        barrb = BitArray(instance._buf)
        ba = bytearray(self._bsz)
        barr = BitArray(ba)

        newoffs = 0
        for offs in range(self._offs, self._offs + self._sz):
            barr[newoffs] = barrb[offs]
            newoffs += 1

        return self.serializer.deserialize(ba, 0, self._bsz)

#
# Proxied properties
#
# Proxy properties are used to expose members of anonymous structures or unions
# at the top-level instance. ProxyProperty implements descriptor protocol like
# MockProperty. Instead of keeping metadata about buffer location it delegates
# all opertions to the proxy target. A proxy target's instance is stored in
# mock instance attribute.
#
#        +-----------------+                     +-----------------+
#        | Mock base class |                     | Mock instance   |
#        +-----------------+                     +-----------------+
#        |                 |                     | Buffer          |
#        |                 |                     |                 |
#        |                 |<--------------------|                 |
#        |                 |                     |                 |
#        +-----------------+                     |                 |
#        | ProxyProperty   |----------+          |                 |
#        +-----------------+          |          +-----------------+
#        |                 |          +--------->| ProxyDesination |
#        +-----------------+                     +-----------------+
#                                                         |
#  +------------------------------------------------------+
#  |
#  |     +-----------------+                     +-------------------+
#  |     | Sub-mock base   |                     | Sub-mock instance |
#  |     | class           |                     +-------------------+
#  |     +-----------------+                     |                   |
#  |     |                 |                     |                   |
#  |     |                 |<--------------------|                   |
#  |     |                 |                     |                   |
#  |     +-----------------+                     |     +-------+     |
#  +---->| MockProperty    |                     |     +-------+     |
#        +-----------------+                     |         |         |
#        |        |        |                     |         |         |
#        +--------|--------+                     +---------|---------+
#                 +----------------------------------------+
#


class ProxyProperty:
    """ Proxies requests to a property on an unrelated class instance.

        This property alows to expose anon struct/union members in a top
        level mock class (Similar to what compilers are doing).
    """

    def __init__(self):
        """ Initializes unound proxy property. """

        self._attrproxy = None
        self._attrname = None

    def __set__(self, instance, value):
        """ Forwards set operation to proxy. """

        proxy = getattr(instance, self._attrproxy)
        setattr(proxy, self._attrname, value)

    def __get__(self, instance, owner = None):
        """ Forwards get operation to proxy. """

        proxy = getattr(instance, self._attrproxy)
        return getattr(proxy, self._attrname)

    def __delete__(self, instance):
        """ Deletes property. """

        raise AttributeError("ProxyProperty instances can't be deleted.")

    def __set_name__(self, owner, name):
        """ Registers owning class property name. """

        self._attrname = name
        self._attrproxy = f'_$proxy_{name}'

    def setProxy(self, instance, proxy):
        """ Bind this descriptor to proxy target. """

        setattr(instance, self._attrproxy, proxy)


#
# Base mock classes
#
# Every mock class is derived from BaseMock class which provides common
# behavior / logic.
#
# One of the goals is to detect broken references between test/macro and kernel
# structures. It is required to disallow creation of new attributes on an instance
# by mock client. For that reason a mock instance can be finalized (frozen).
# This prevents user from accidentally creating members that does not exist in
# original structure.
#


class BaseMock(ABC):
    """ Abstract base class serving as a base of every scripted process mock. """

    __frozen = False

    def __init__(self, size: int):
        """ Init mock with given offset and size. """

        self._size = size
        self.log = lldb.test_logger.getChild(self.__class__.__name__)


    def __setattr__(self, key: str, value: typing.Any) -> None:
        """ Sets new attribute value or creates one (if not frozen). """

        # Raise exception if new attribute is being created on frozen mock.
        if self.__frozen and not hasattr(self, key):
            self.log.debug("Frozen mock missing attribute %s", key)
            raise TypeError(f"Can't add {key} as {self} is a frozen")

        return super().__setattr__(key, value)

    def freeze(self):
        """ Freeze the mock so no additional attributes can be created. """

        self.__frozen = True

    # Please be conservative when adding methods / attributes here.
    # Each such method may conflict with members a mock sub-class may create.

    @property
    def size(self):
        """ Size in bytes of this mock. """

        return self._size

    def fromDict(self, members):
        """ Initialize mock members from dictionary. """

        for k, v in members.items():
            if isinstance(v, dict):
                getattr(self, k).fromDict(v)

            setattr(self, k, v)

        return self

    @abstractmethod
    def getData(self):
        """ Returns byte representation of the mock. """

    @abstractmethod
    def setData(self, data):
        """ Restores mock attributes from bytes. """

        # Take care when implementing this method as sub-mocks may reference
        # existing data instance. Replacing underlying buffer with new one
        # may result in data no longer being shared with sub-mocks.


class RawMock(BaseMock):
    """ Simple mock that wraps raw data that are going to be placed in memory.

        This mock does not have any attributes. It is possible to provide a
        serializer to allow converstion from types like string.
    """

    def __init__(self, size: int, serializer=NoSerializer()):
        """ A mock that holds raw bytes for given offset/size range. """

        super().__init__(size)
        self._data = serializer.default()
        self.serializer = serializer
        self.freeze()

    def getData(self):
        """ Returns memory view based on the data in this mock. """

        return memoryview(self._data)

    def setData(self, data):
        """ Sets value of the mock. """

        if self.serializer:
            self._data = self.serializer.serialize(data, self.size)
        else:
            self._data = data

    def fromDict(self, members):
        """ Not supported by raw memory mock """
        raise NotImplementedError("RawMock can't be populated from dict.")

    @staticmethod
    def fromBufferedIO(fromIO: io.BufferedIOBase) -> 'RawMock':
        """ Populate mock data from I/O intance. """

        data = fromIO.read()
        mock = RawMock(len(data))
        mock.setData(data)

        return mock

class ArrayMock(BaseMock):
    """ Inserts array of mocks into target's memory.

        High-level wrapper that constructs array of mocks of given type.
        All mocks share same underlying buffer.
    """

    def __init__(self, sbtype: lldb.SBType, parentBuf=None):
        """ """
        super().__init__(sbtype.GetByteSize())

        # Top level array mock will allocate buffer. Otherwise it will distribute
        # sub-mocks across parent's buffer.
        if parentBuf:
            self._data = memoryview(parentBuf)[:self._size]
        else:
            self._data = bytearray(self._size)

        elem_sbtype = sbtype.GetArrayElementType()
        self._count = self._size // elem_sbtype.GetByteSize()

        self._arrmocks = []
        offs = 0
        for _ in range(self._count):
            submock = MockFactory.createFromType(elem_sbtype, 0,
                        memoryview(self._data)[offs: offs + sbtype.GetByteSize()])
            self._arrmocks.append(submock)
            offs += elem_sbtype.GetByteSize()

    def getData(self):
        return memoryview(self._data)

    def setData(self, data):
        self._data[0: len(data)] = data

    def fromDict(self, members):
        for k, v in members.items():
            idx = int(k)
            self._arrmocks[idx].fromDict(v)

        return self

    def __getitem__(self, key):
        """ Returns sub-mock at given index. """
        if isinstance(key, slice):
            return [self[ii] for ii in range(*key.indices(len(self)))]

        return self._arrmocks[key]


class MemoryMock(BaseMock):
    """ Inserts serialized MemoryMock directly into target's memory. """

    def __init__(self, sbtype: lldb.SBType, buf):
        super().__init__(sbtype.GetByteSize())
        self._sbtype = sbtype
        self._anon_mocks = []
        self._buf = buf

    def setData(self, data: bytes):
        """ Set underlying buffer and reconstruct mock values. """
        self.log.debug("setData refereshing mocks")

        # Setting data on a sub-mock is not allowed.
        # Sub-mocks are always using memoryviews.
        if isinstance(self._buf, memoryview):
            raise AttributeError("Can't set data on a sub-mock.")

        self._buf[0: len(data)] = data

    def getData(self):
        """ Return memory view of mock's data buffer. """

        return memoryview(self._buf)


#
# Mock factories
#
# Abstracts away mock creation from the actual mock instances. Most of the
# factories are singletons.
#

class MockFactory(ABC):
    """ Abstract base class factory.
    """

    def __init__(self):
        """ Initialize factory. """
        self.log = lldb.test_logger.getChild(self.__class__.__name__)

    @abstractmethod
    def create_mock(self, sbtype: lldb.SBType, offs: int = 0, parent_buf = None):
        """ Constructs concrete mock class instance for given SBType. """

    @staticmethod
    def createFromType(mocktype: typing.Union[str, lldb.SBType],
                       offs: int = 0, parent_buf = None) -> 'MemoryMock':
        """ Top-level factory method available to users. """

        # Lookup type to be created
        sbtype = lookup_type(mocktype)
        if not sbtype or not sbtype.IsValid():
            raise AttributeError("Unknown type")

        # Resolve typedefs to canconical type (to avoid typedefs)
        sbtype = sbtype.GetCanonicalType()

        # Select factory based on type.
        factory = SimpleTypeFactory()
        type_class = sbtype.GetTypeClass()

        # Structures/Unions
        if type_class == lldb.eTypeClassStruct or type_class == lldb.eTypeClassUnion:
            factory = CompoundTypeFactory()

        # Arrays
        if type_class == lldb.eTypeClassArray:
            factory = ArrayTypeFactory()

        # Use factory's method to create mock class instance.
        return factory.create_mock(sbtype, offs, parent_buf)


class SimpleTypeFactory(MockFactory, metaclass=Singleton):
    """ Constructs mocking class for a simple types. """

    def create_mock(self, sbtype: lldb.SBType, offs: int = 0, parent_buf = None):
        """ Create RawMock instance for simple types."""

        self.log.debug("Creating mock for %s", sbtype.GetName())

        # Simple type does not have any members.
        if sbtype.GetNumberOfFields() > 0:
            raise AttributeError("Not a simple type")

        # Return new mock instance and freeze it.
        mock = RawMock(size=sbtype.GetByteSize(),
                       serializer=Serializer.createSerializerForType(sbtype))
        mock.freeze()
        return mock


class ArrayTypeFactory(MockFactory, metaclass=Singleton):
    """ Constructs mocking class for array types. """

    def create_mock(self, sbtype: lldb.SBType, offs: int = 0, parent_buf = None):
        """ Delegate array type creation and construct an array. """

        self.log.debug("Creating mock for %s", sbtype.GetName())
        mock = ArrayMock(sbtype)
        mock.freeze()
        return mock


#
# Compound type mocks
#
# A compound mock tries to convert SBType to a native Python class. Such conversion
# happens in three phases:
#
#    1. SBType gets converted to new Python class defintion with MockProperties.
#    2. Mock is created as an instance of the new class.
#    3. Postprocessing resolves binding / nesting.
#    4. Mocks are frozen and returned to a client.
#
# It may be required to repeat steps above multiple times to recrete whole
# type hierarchy. The top level mock is byte array provider for the whole
# hierarchy of sub-mocks. This avoids the need for complex sync between class
# attributes and final byte array holding serialized copy of the type value.
# At the same time it makes handling of unions easier because it is possible
# to simply create overlaping sub-mocks that share same parent's buffer area.
#
# Example - Simple type:
#
#    struct node {
#        uint64_t memA;
#        uint64_t memB;
#    }
#
# First a Mock_node class is created by factory. This class gets two properties
#    - MockProperty<int> memA which spans indexes (0 .. 7)
#    - MockProperty<int> memB which spans indexes (8 .. 15)
#
# An instance of the Mock_node class is created which will hold the buffer
# Any operation on a MockProperty will result in serializer/deserializer being
# invoked directly on the associated buffer area.
#
# Example - Nested structures:
#
#    struct node_t {
#        struct {
#             uint64_t member;
#        } sub_node;
#    }
#
# Nested structures are handled by creation of sub-mock for given type
# of a compound member. The only difference is that sub-mock instance will not
# have its own buffer. Instead it is given view of parent's buffer arrea covered
# by the sub-mock. This way all changes are propagated to the parent and all
# offsets within sub-mock can be applied directly as the view itself is offset
# from the start of buffer.
#
# Example - Anonymous members
#
#    struct node_t {
#        struct {
#            uint64_t member;
#        }
#    }
#
# This is more complex example because there is no way how to reference anon
# type in the structure. However C compiler allows accessing such members by
# thier names.
#
# CompoundMock supports anonymous members in a following way:
#
#     1. A nested sub-mock is created like in example above.
#     3. A ProxyProperty is added to top level mock (unbound) for every anon
#        member's child.
#     2. Reference is kept in parent's _anon_mocks (becasue there is no member)
#     4. Sub-mocks are instantiated
#     5. Proxy lookup will find sub-mock instances providing a member and
#        bind top-level proxies to it.
#
# See ProxyProperty comment above for illustration.
#
# This way a top-level mock delegates property handling to a submock. Submock
# then propagates all changes back to top-level mock's buffer.
#


class CompoundTypeFactory(MockFactory, metaclass=Singleton):
    """ Constructs mock class and instance for non-trivial types. """

    cache = {}

    def _make_property(self, member: lldb.SBTypeMember):
        """ Creates correct property type based on type member. """

        if member.IsBitfield():
            self.log.debug("Creating BitfieldProperty for %s", member.GetName())
            return BitfieldProperty(
                member.GetOffsetInBits(),
                member.GetBitfieldSizeInBits(),
                Serializer.createSerializerForType(member.GetType()))

        self.log.debug("Creating MockProperty for %s", member.GetName())
        return MockProperty(
            member.GetOffsetInBytes(),
            member.GetType().GetByteSize(),
            Serializer.createSerializerForType(member.GetType()))

    def _createMockClass(self, sbtype: lldb.SBType, offs: int = 0):
        """ Converts SBType into a new mock base class. """

        self.log.debug("Creating mock class for %s", sbtype.GetName())

        # Try cache first
        clsname = f'MockBase_{sbtype.GetName()}_{offs}'
        cls = self.cache.get(clsname, None)
        if cls is not None:
            self.log.debug("Found in cache %s", clsname)
            return cls

        attrs = {}

        # Add all direct members as MockProperty.
        for t in sbtype.get_members_array():

            # Create MockProperty for members with simple data types.
            if t.GetType().GetNumberOfFields() == 0:
                attrs[t.GetName()] = self._make_property(t)


            # Skip creation of proxied properties for sub-mocks. There is no need
            # to build a chain. Top-level mock will bind directly to desired
            # sub-mock.
            if offs != 0:
                continue

            # Create ProxyProperty for anonymous sub-members so we can later
            # establish the forwarding to the mock that overlays this area.
            if t.GetType().IsAnonymousType():

                def visit_anon(sbtype):
                    for at in sbtype.get_members_array():
                        if at.GetType().IsAnonymousType():
                            yield from visit_anon(at.GetType())
                        else:
                            yield at

                for at in visit_anon(t.GetType()):
                    self.log.debug("Adding anon proxy for %s", at.GetName())
                    attrs[at.GetName()] = ProxyProperty()

            # Compound types are not handled at mock class level. They are
            # going to be added to the class instance.

        # Insert class into cache. anon types are ignored as there may be
        # name conflicts.
        self.log.debug("Created new mock class %s", clsname)

        clsname = f'MockBase_{sbtype.GetName()}_{offs}'
        cls = type(clsname, (MemoryMock,), attrs)

        # No caching of anon types
        if sbtype.IsAnonymousType():
            self.log.debug("Anon type not caching")
            return cls

        if clsname in self.cache:
            raise AttributeError("Already in cache !!")

        self.cache[clsname] = cls
        return cls

    def create_mock(self, sbtype: lldb.SBType, offs: int = 0, parent_buf = None):
        """ Creates mock instance of mock class created from SBType. """

        if sbtype.GetNumberOfFields() == 0:
            raise AttributeError("Not a compound type")

        # Top level mocks are buffer providers
        if not parent_buf:
            buf = bytearray(sbtype.GetByteSize())
            self.log.debug("%s size is %d", sbtype.GetName(), sbtype.GetByteSize())
        else:
            buf = memoryview(parent_buf)[offs: offs + sbtype.GetByteSize()]

        # Construct new mock base class.
        mock_class = self._createMockClass(sbtype, offs)
        mock_inst = mock_class(sbtype, buf)

        # Pre-populate all properties with default values.
        for prop, value in mock_class.__dict__.items():
            if isinstance(value, MockProperty):
                self.log.debug(f'Setting default for {prop}')
                setattr(mock_inst, prop, value.serializer.default())

        # Instantiate regular sub-mocks
        for t in sbtype.get_members_array():
            if t.GetType().GetNumberOfFields() == 0:
                continue

            # Create sub-mocks for regular structures/unions
            submock = MockFactory.createFromType(t.GetType(), t.GetOffsetInBytes(), buf)
            if not t.GetType().IsAnonymousType():
                self.log.debug("Creating anon sub-mock %s at %d",
                               t.GetName(), t.GetOffsetInBytes())
                setattr(mock_inst, t.GetName(), submock)
                continue

            # Create and connect instances
            mock_inst._anon_mocks.append(submock)

        # Resolve proxies
        resolve = {
            k:p for (k, p)
            in mock_class.__dict__.items()
            if isinstance(p, ProxyProperty)
        }

        # Assumption is there are no conflicts (compiler would refuse to build the code)

        def visit_anon_mocks(mock):
            for m in mock._anon_mocks:
                yield from m._anon_mocks
                yield m

        for am in visit_anon_mocks(mock_inst):
            for t in am._sbtype.get_members_array():
                if t.GetName() in resolve:
                    resolve[t.GetName()].setProxy(mock_inst, am)
                    self.log.debug("Resolving %s", t.GetName())
                    del resolve[t.GetName()]

        # Fail if there are unresolved members.
        if resolve:
            raise TypeError('Unresolved proxies in a mock class')

        # Construct mock instance
        mock_inst.freeze()
        return mock_inst
