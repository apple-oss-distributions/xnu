import functools
import inspect
import numbers
import struct
import sys

import lldb

__all__ = []

UPCASTS = {}

#
# List of Quirks, once fixed, replace the booleans with an evaluation
# of whether the lldb being used has the fix or not.
#

#
# rdar://99785324 (GetValueAsUnsigned performs sign extension
#                  when it REALLY shouldn't on bitfields)
#
QUIRK_99785324 = True

#
# rdar://99806493 (SBValue.Cast() is not doing the right thing with PAC)
#
QUIRK_99806493 = True

#
# rdar://100103405 (Default value for target.prefer-dynamic-value makes
#                  macros 40x as slow when connected to Astris)
#
QUIRK_100103405 = True

#
# rdar://100162262 ([correctness] Multiple dereferences do not result
#                  in the same load address in some cases depending
#                  on whether the original value is a pointer created
#                  with AddressOf() or not.)
#
QUIRK_100162262 = True

#
# rdar://102642763 (LLDB macros are unable to access member of anon struct
#                  or union in C++ class)
#
QUIRK_102642763 = True

#
# rdar://104494282 (Lldb computes correct "Value As Address" but Dereference()s
#                   wrong)
#
QUIRK_104494282 = True


I8_STRUCT  = struct.Struct('b')
I16_STRUCT = struct.Struct('h')
I32_STRUCT = struct.Struct('i')
I64_STRUCT = struct.Struct('q')

U8_STRUCT  = struct.Struct('B')
U16_STRUCT = struct.Struct('H')
U32_STRUCT = struct.Struct('I')
U64_STRUCT = struct.Struct('Q')

FLT_STRUCT = struct.Struct('f')
DBL_STRUCT = struct.Struct('d')


def lldbwrap_raise(exn, fn, reason, *args, **kwargs):
    """
    Helper to form a helpful exception string for the generic lldb.SB*
    checked wrappers

    @param exn (Exception type)
        The type of exception to raise

    @param fn (Function)
        The function that failed (approximately)

    @param reason (string)
        A reason string to append

    @params *args, **kwargs
        The arguments that have been passed to @c fn
        in order to pretty pring them in something useful
    """
    args_str = []

    for arg in args:
        if isinstance(arg, lldb.SBValue):
            args_str.append("<lldb.SBValue ({} &){:#x}>".format(
                lldb.SBValue(arg).GetType().GetDisplayTypeName(),
                lldb.SBValue(arg).GetLoadAddress())
            )
        elif isinstance(arg, lldb.SBType):
            args_str.append("<lldb.SBType {}>".format(lldb.SBType(arg).GetDisplayTypeName()))
        elif isinstance(arg, numbers.Integral):
            args_str.append("{:#x}".format(arg))
        else:
            args_str.append(repr(arg))

    if len(kwargs) > 0:
        args_str.append("...")

    if reason:
        raise exn("{}({}) failed: {}".format(
            fn.__name__, ", ".join(args_str), reason))
    raise exn("{}({}) failed".format(fn.__name__, ", ".join(args_str)))


def lldbwrap_update_class_dict(basename, basecls, attr):
    """
    Make the extension dictionary for our synthesized classes

    This function will add wrappers around certain functions
    that will inspect their return type, and when it is
    of one of the @c UPCASTS ones, will monkey patch
    the return value __class__.

    It would be cleaner to invoke a "copy constructor", however
    it has a very high cost, so this brittle monkey patching
    is used instead.
    """

    def _make_upcast_wrapper(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            result = fn(*args, **kwargs)
            upcast = UPCASTS.get(result.__class__)
            if upcast: upcast(result)
            return result

        return wrapper

    def _make_checked_upcast_wrapper(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            result = fn(*args, **kwargs)
            upcast = UPCASTS.get(result.__class__)
            if not upcast:
                return result
            upcast(result)
            if result.IsValid():
                return result
            lldbwrap_raise(ValueError, fn, None, *args, **kwargs)

        return wrapper

    @classmethod
    def xUpcast(cls, value):
        value.__class__ = cls

    #
    # Those methods return scalars, and are very popular
    # wrapping only makes them slow with no benefit.
    #
    DO_NOT_WRAP = set([
        'GetByteSize',
        'GetAddressByteSize',
        'GetLoadAddress',
        'GetName',
        'GetOffsetInBits',
        'GetOffsetInBytes',
        'GetStopID',
        'GetTypeFlags',
        'GetUniqueID',
        'GetValueAsAddress',
        'GetValueAsSigned',
        'GetValueAsUnsigned',
        'TypeIsPointerType',
        'IsValid',
        'SetPreferDynamicValue'
    ])

    DO_NOT_WRAP_PREFIX = [
        '__',           # do not wrap magic python functions
        'Is',           # LLDB's "Is*" APIs return booleans
        'GetNum',       # LLDB's "GetNum*" APIs return integers
        'GetIndex',     # LLDB's "GetIndex*" APIs return integers
    ]

    for fname, value in inspect.getmembers(basecls):
        if fname in DO_NOT_WRAP:
            continue

        elif any(fname.startswith(pfx) for pfx in DO_NOT_WRAP_PREFIX):
            continue

        elif inspect.isfunction(value) or inspect.ismethod(value):
            attr.setdefault(fname, _make_upcast_wrapper(value))
            attr.setdefault('chk' + fname, _make_checked_upcast_wrapper(value))
            attr.setdefault('raw' + fname, value)

        elif isinstance(value, property):
            attr[fname] = property(_make_upcast_wrapper(value.fget), value.fset, doc=value.__doc__)

    attr.setdefault('xUpcast', xUpcast)


class LLDBWrapMetaclass(type):
    """ Metaclass used for manual definitions of lldb.SB* subclasses """

    def __new__(cls, name, bases, attr):
        lldbwrap_update_class_dict(name, bases[0], attr)
        return type.__new__(cls, name, bases, attr)


class SBProcess(lldb.SBProcess, metaclass=LLDBWrapMetaclass):

    #
    # Manually written checked wrappers
    #

    @functools.wraps(lldb.SBProcess.ReadMemory)
    def chkReadMemory(self, addr, size):
        err = lldb.SBError()
        res = self.ReadMemory(addr, size, err)
        if err.Success():
            return res
        lldbwrap_raise(IOError, self.ReadMemory, err.GetCString(),
            self, addr, size)

    @functools.wraps(lldb.SBProcess.WriteMemory)
    def chkWriteMemory(self, addr, buf):
        err = lldb.SBError()
        res = self.WriteMemory(addr, buf, err)
        if err.Success():
            return res
        lldbwrap_raise(IOError, self.WriteMemory, err.GetCString(),
            self, addr, buf)

    @functools.wraps(lldb.SBProcess.ReadCStringFromMemory)
    def chkReadCStringFromMemory(self, addr, max_size):
        err = lldb.SBError()
        res = self.ReadCStringFromMemory(addr, max_size, err)
        if err.Success():
            return res
        lldbwrap_raise(IOError, self.ReadCStringFromMemory, err.GetCString(),
            self, addr, max_size)

    @functools.wraps(lldb.SBProcess.ReadUnsignedFromMemory)
    def chkReadUnsignedFromMemory(self, addr, byte_size):
        err = lldb.SBError()
        res = self.ReadUnsignedFromMemory(addr, byte_size, err)
        if err.Success():
            return res
        lldbwrap_raise(IOError, self.ReadUnsignedFromMemory, err.GetCString(),
            self, addr, byte_size)

    @functools.wraps(lldb.SBProcess.ReadPointerFromMemory)
    def chkReadPointerFromMemory(self, addr):
        err = lldb.SBError()
        res = self.ReadPointerFromMemory(addr, err)
        if err.Success():
            return res
        lldbwrap_raise(IOError, self.ReadPointerFromMemory, err.GetCString(),
            self, addr)


class SBTarget(lldb.SBTarget, metaclass=LLDBWrapMetaclass):

    #
    # Manually written checked wrappers
    #

    @functools.wraps(lldb.SBTarget.ReadMemory)
    def chkReadMemory(self, addr, buf):
        err = lldb.SBError()
        res = self.ReadMemory(addr, buf, err)
        if err.Success():
            return res
        lldbwrap_raise(IOError, self.ReadMemory, err.GetCString(),
            self, addr, buf)


    #
    # Extensions
    #

    def xReadBytes(self, addr, size):
        """
        Reads memory from the current process's address space and removes any
        traps that may have been inserted into the memory.

        @param addr (int)
            The address to start reading at

        @param size (int)
            The size of the read to perform

        @returns (bytes)
        """
        return bytes(self.GetProcess().chkReadMemory(addr, size))

    def xReadCString(self, addr, max_size):
        """
        Reads a NULL terminated C string from the current process's address space.
        It returns a python string of the exact length, or truncates the string if
        the maximum character limit is reached. Example: ::

        @param addr (int)
            The address to start reading at

        @param max_size (int)
            The maximum size of the string

        @returns (str)
        """

        return self.GetProcess().chkReadCStringFromMemory(addr, max_size)

    def xReadInt8(self, addr):
        """ Conveniency wrapper to read an int8_t at the specified address """
        return int(I8_STRUCT.unpack(self.xReadBytes(addr, 1))[0])

    def xReadInt16(self, addr):
        """ Conveniency wrapper to read an int16_t at the specified address """
        return int(I16_STRUCT.unpack(self.xReadBytes(addr, 2))[0])

    def xReadInt32(self, addr):
        """ Conveniency wrapper to read an int32_t at the specified address """
        return int(I32_STRUCT.unpack(self.xReadBytes(addr, 4))[0])

    def xReadInt64(self, addr):
        """ Conveniency wrapper to read an int64_t at the specified address """
        return int(I64_STRUCT.unpack(self.xReadBytes(addr, 8))[0])

    def xReadUInt8(self, addr):
        """ Conveniency wrapper to read an uint8_t at the specified address """
        return int(U8_STRUCT.unpack(self.xReadBytes(addr, 1))[0])

    def xReadUInt16(self, addr):
        """ Conveniency wrapper to read an uint16_t at the specified address """
        return int(U16_STRUCT.unpack(self.xReadBytes(addr, 2))[0])

    def xReadUInt32(self, addr):
        """ Conveniency wrapper to read an uint32_t at the specified address """
        return int(U32_STRUCT.unpack(self.xReadBytes(addr, 4))[0])

    def xReadUInt64(self, addr):
        """ Conveniency wrapper to read an uint64_t at the specified address """
        return int(U64_STRUCT.unpack(self.xReadBytes(addr, 8))[0])

    def xReadLong(self, addr):
        """ Conveniency wrapper to read a long at the specified address """
        if self.GetProcess().GetAddressByteSize() == 8:
            return int(I64_STRUCT.unpack(self.xReadBytes(addr, 8))[0])
        return int(I32_STRUCT.unpack(self.xReadBytes(addr, 4))[0])

    def xReadULong(self, addr):
        """ Conveniency wrapper to read a long at the specified address """
        if self.GetProcess().GetAddressByteSize() == 8:
            return int(U64_STRUCT.unpack(self.xReadBytes(addr, 8))[0])
        return int(U32_STRUCT.unpack(self.xReadBytes(addr, 4))[0])

    def xReadFloat(self, addr):
        """ Conveniency wrapper to read a float at the specified address """
        return FLT_STRUCT.unpack(self.xReadBytes(addr, 4))[0]

    def xReadDouble(self, addr):
        """ Conveniency wrapper to read a double at the specified address """
        return DBL_STRUCT.unpack(self.xReadBytes(addr, 8))[0]


    def xIterAsStruct(self, spec, addr, count):
        """
        Iterate the memory as defined by the specified struct spec

        @param spec (struct.Struct)
            A struct unpack spec

        @param addr (int)
            The address to start ieterating from

        @param count (int)
            The number of structs to read
        """

        if not count:
            return ()

        size = spec.size
        data = self.xReadBytes(addr, count * size)
        if hasattr(spec, 'iter_unpack'):
            return spec.iter_unpack(data)

        # Python 2
        return (
            spec.unpack(data[i : i + size])
            for i in range(0, count * size, size)
        )


    def xIterAsScalar(self, spec, addr, count):
        """
        Iterate the memory as defined by the specified scalar spec

        Unlike xIterAsStruct() this will return the first element
        of the struct.Strict.iter_unpack() tuple.

        @param spec (struct.Struct)
            A struct unpack spec

        @param addr (int)
            The address to start ieterating from

        @param count (int)
            The number of scalars to read
        """

        if not count:
            return ()

        size = spec.size
        data = self.xReadBytes(addr, count * size)
        if hasattr(spec, 'iter_unpack'):
            return (e[0] for e in spec.iter_unpack(data))

        # Python 2
        return (
            int(spec.unpack(data[i : i + size])[0])
            for i in range(0, count * size, size)
        )

    def xStripPtr(self, sbvalue):
        """ Strips top bits in a pointer value """

        if strip := getattr(self, '_strip_ptr', None):
            return strip(sbvalue)

        is_tagged = False
        # is_tagged = self.FindFirstGlobalVariable('kasan_tbi_enabled').IsValid()

        def stripPtr(sbvalue: lldb.SBValue):
            if sbvalue.GetValueAsAddress() != sbvalue.GetValueAsUnsigned():
                addr = sbvalue.GetValueAsAddress()
                sbv_new = sbvalue.CreateValueFromExpression(None, '(void *)' + str(addr))
                return sbv_new.Cast(sbvalue.GetType())

            return sbvalue

        if is_tagged:
            strip = lambda sbv: stripPtr(sbv)
        else:
            strip = lambda sbv : sbv

        self._strip_ptr = strip
        return strip(sbvalue)

    def xIterAsInt8(self, addr, count):
        """ Conveniency wrapper to xIterAsScalar() on int8_t """
        return self.xIterAsScalar(I8_STRUCT, addr, count)

    def xIterAsInt16(self, addr, count):
        """ Conveniency wrapper to xIterAsScalar() on int16_t """
        return self.xIterAsScalar(I16_STRUCT, addr, count)

    def xIterAsInt32(self, addr, count):
        """ Conveniency wrapper to xIterAsScalar() on int32_t """
        return self.xIterAsScalar(I32_STRUCT, addr, count)

    def xIterAsInt64(self, addr, count):
        """ Conveniency wrapper to xIterAsScalar() on int64_t """
        return self.xIterAsScalar(I64_STRUCT, addr, count)

    def xIterAsUInt8(self, addr, count):
        """ Conveniency wrapper to xIterAsScalar() on uint8_t """
        return self.xIterAsScalar(U8_STRUCT, addr, count)

    def xIterAsUInt16(self, addr, count):
        """ Conveniency wrapper to xIterAsScalar() on uint16_t """
        return self.xIterAsScalar(U16_STRUCT, addr, count)

    def xIterAsUInt32(self, addr, count):
        """ Conveniency wrapper to xIterAsScalar() on uint32_t """
        return self.xIterAsScalar(U32_STRUCT, addr, count)

    def xIterAsUInt64(self, addr, count):
        """ Conveniency wrapper to xIterAsScalar() on uint64_t """
        return self.xIterAsScalar(U64_STRUCT, addr, count)

    def xIterAsLong(self, addr, count):
        """ Conveniency wrapper to xIterAsScalar() on long """
        if self.GetProcess().GetAddressByteSize() == 8:
            return self.xIterAsScalar(I64_STRUCT, addr, count)
        return self.xIterAsScalar(I32_STRUCT, addr, count)

    def xIterAsULong(self, addr, count):
        """ Conveniency wrapper to xIterAsScalar() on unsigned long """
        if self.GetProcess().GetAddressByteSize() == 8:
            return self.xIterAsScalar(U64_STRUCT, addr, count)
        return self.xIterAsScalar(U32_STRUCT, addr, count)

    def xIterAsFloat(self, addr, count):
        """ Conveniency wrapper to xIterAsScalar() on float """
        return self.xIterAsScalar(FLT_STRUCT, addr, count)

    def xIterAsDouble(self, addr, count):
        """ Conveniency wrapper to xIterAsScalar() on double """
        return self.xIterAsScalar(DBL_STRUCT, addr, count)


    def xCreateValueFromAddress(self, name, addr, ty):
        """
        Create an SBValue with the given name by treating the memory starting
        at addr as an entity of type.

        More tolerant wrapper around CreateValueFromAddress() that accepts
        for @c name to be None and @c addr to be an int.

        @param name (str or None)
            The name of the resultant SBValue

        @param addr (int or lldb.SBAddress)
            The address of the start of the memory region to be used.

        @param ty (lldb.SBType)
            The type to use to interpret the memory starting at addr.

        @return (lldb.SBValue)
            An SBValue of the given type.

        @raises ValueError
            For various error conditions.
        """

        if not isinstance(addr, lldb.SBAddress):
            addr = self.rawResolveLoadAddress(addr)

        if name is None:
            # unlike SBValue's variant, SBTargets's will fail to produce
            # a value if the name is None, don't ask.
            name = 'newvalue'

        v = self.CreateValueFromAddress(name, addr, ty)
        if v.IsValid():
            if QUIRK_100103405 and not addr:
                v.SetPreferDynamicValue(0)
            return v

        lldbwrap_raise(ValueError, self.CreateValueFromAddress, None, name)


class SBType(lldb.SBType, metaclass=LLDBWrapMetaclass):

    #
    # Extensions
    #

    def _findFieldOffsetByName(self, name):
        """ internal helper """

        for idx in range(self.GetNumberOfFields()):
            field = self.GetFieldAtIndex(idx)
            fname = field.GetName()

            if fname == name:
                return field.GetOffsetInBytes(), field.GetType()

            if fname is None:
                offs, ty = field.GetType()._findFieldOffsetByName(name)
                if offs is not None:
                    return offs + field.GetOffsetInBytes(), ty

        return None, None

    def _findFieldOffsetByPath(self, path):
        """ internal helper """

        offs = 0
        ty   = self

        key = path[1:] if path[0] == '.' else path

        while key != '':
            name, _, key = key.partition('.')
            index = None

            if name[-1] == ']':
                name, _, index = name[:-1].partition('[')
                if not index.isdigit():
                    raise KeyError("Invalid path '{}'".format(path))
                index = int(index)

            f_offs, ty = ty._findFieldOffsetByName(name)
            if f_offs is None:
                return None, None, None

            offs += f_offs
            if index is not None:
                if ty.GetTypeFlags() & lldb.eTypeIsArray:
                    ty = ty.GetArrayElementType()
                else:
                    ty = ty.GetPointeeType()
                offs += ty.GetByteSize() * index

        return offs, ty, name

    def xGetFieldOffset(self, path_or_name):
        """
        Returns offsetof(type, path_or_name) in bytes.

        @param path_or_name (str)
            The field path or name to compute the offset of

        @return (int or None)
            The requested offset of the field within the type,
            or None if the field wasn't found
        """
        return self._findFieldOffsetByPath(path_or_name)[0]

    def xContainerOfTransform(self, path):
        """
        Returns a function that can be used to apply a "__container_of"
        transformation repeatedly (by field path).

        @param path_or_name (str)
            The field path or name to compute the offset of

        @returns (function)
            A function that returns the value resulting of
            __container_of(value, type_t, path) for this type.
        """

        offs = self.xGetFieldOffset(path)

        return lambda x: x.xCreateValueFromAddress(None, x.GetLoadAddress() - offs, self)

    def xContainerOf(self, path_or_name, value):
        """ same as self.xContainerOfTransform(path_or_name)(value) """

        return self.xContainerOfTransform(path_or_name)(value)


class SBValue(lldb.SBValue, metaclass=LLDBWrapMetaclass):

    if QUIRK_100103405:
        @classmethod
        def xUpcast(cls, value):
            #
            # LLDB insists on trying to translate "NULL" for `void *`
            # when dynamic values are enabled. It never caches the
            # negative result which can yield really slow performance.
            #
            # Work it around by disabling dynamic values, looking at whether
            # it's vaguely looking like a pointer and its value is a NULL
            # pointer, and if not, turn dynamic values back on
            #
            # This check is extremely expensive and makes shorcuts,
            # such as testing against "8" (sizeof(void *) on LP64)
            # in order to delay realizing the type as much as possible
            #
            dyn = value.GetPreferDynamicValue()
            if dyn:
                value.SetPreferDynamicValue(0)
                if (value.GetByteSize() != 8 or
                        value.GetValueAsUnsigned() or
                        not value.TypeIsPointerType()):
                    value.SetPreferDynamicValue(dyn)

            value.__class__ = cls

    #
    # Manually written checked wrappers
    #

    @functools.wraps(lldb.SBValue.GetValueAsSigned)
    def chkGetValueAsSigned(self):
        err = lldb.SBError()
        res = self.GetValueAsSigned(err)
        if res or err.Success():
            return res
        lldbwrap_raise(ValueError, self.chkGetValueAsSigned, err.GetCString(),
            self)

    @functools.wraps(lldb.SBValue.GetValueAsUnsigned)
    def chkGetValueAsUnsigned(self):
        err = lldb.SBError()
        res = self.GetValueAsUnsigned(err)
        if res or err.Success():
            return res
        lldbwrap_raise(ValueError, self.chkGetValueAsUnsigned, err.GetCString(),
            self)

    @functools.wraps(lldb.SBValue.SetValueFromCString)
    def chkSetValueFromCString(self, value_str):
        err = lldb.SBError()
        if not self.SetValueFromCString(value_str, err):
            lldbwrap_raise(ValueError, self.chkSetValueFromCString, err.GetCString(),
                self, value_str)

    @functools.wraps(lldb.SBValue.SetData)
    def chkSetData(self, data):
        err = lldb.SBError()
        if not self.SetData(data, err):
            lldbwrap_raise(ValueError, self.chkSetData, err.GetCString(),
                self, data)

    if QUIRK_99806493:
        def Cast(self, ty):
            v = super().Cast(ty)
            SBValue.xUpcast(v)

            if not v.IsValid() or not v.TypeIsPointerType():
                return v

            #
            # NULL is fine, needs no PAC stripping,
            # and it makes CreateValueFromAddress behave funny.
            #
            addr = v.GetValueAsAddress()
            if addr == 0:
                return v

            #
            # Casting from a pointer type to another
            # is not stripping __ptrauth, let's fix it
            #
            nv = v.rawCreateValueFromAddress(v.GetName(), addr, ty)
            nv.SetPreferDynamicValue(v.GetPreferDynamicValue())
            v = nv.AddressOf().Cast(ty)

            if QUIRK_100162262:
                nv = v.Persist()
                nv.SetPreferDynamicValue(v.GetPreferDynamicValue())
                v = nv

            # no need for QUIRK_100103405, can't be NULL
            v.__class__ = SBValue
            return v

        def chkCast(self, ty):
            v = self.Cast(ty)
            if v.IsValid():
                return v

            lldbwrap_raise(ValueError, SBValue.Cast, None, self, ty)

    if QUIRK_100162262:
        def AddressOf(self):
            v = super().AddressOf().Persist()
            # no need for QUIRK_100103405
            v.__class__ = SBValue
            return v

        def chkAddressOf(self):
            v = self.AddressOf()
            if v.IsValid():
                return v

            lldbwrap_raise(ValueError, SBValue.AddressOf, None, self)

    if QUIRK_104494282:
        def Dereference(self):
            addr = self.GetValueAsAddress()
            if addr == self.GetValueAsUnsigned():
                v = super().Dereference()
                SBValue.xUpcast(v)
                return v

            return self.xCreateValueFromAddress(self.GetName(),
                addr, self.GetType().GetPointeeType())

    if QUIRK_102642763:
        def GetChildMemberWithName(self, name):
            v = self.rawGetChildMemberWithName(name)
            SBValue.xUpcast(v)
            if v.IsValid():
                return v

            # Emulate compiler logic and visit all nested anon struct/unions.
            if self.GetType().IsPointerType():
                return self.xDereference().GetChildMemberWithName(name)

            offs, mty = self.GetType()._findFieldOffsetByName(name)
            if offs is None:
                # LLDB returns instance of SBValue that is set as invalid.
                # Re-use the invalid one from initial lookup.
                return v

            return self.xCreateValueFromAddress(name, self.GetLoadAddress() + offs, mty)

        def GetValueForExpressionPath(self, path):
            v = self.rawGetValueForExpressionPath(path)
            SBValue.xUpcast(v)
            if v.IsValid():
                return v

            # Emulate compiler logic and visit all nested anon struct/unions.
            if self.GetType().IsPointerType():
                return self.xDereference().GetValueForExpressionPath(path)

            # Emulate compiler logic and visit all nested anon struct/unions.
            offs, mty, name = self.GetType()._findFieldOffsetByPath(path)
            if offs is None:
                # LLDB returns instance of SBValue that is set as invalid.
                # Re-use the invalid one from initial lookup.
                return v

            return self.xCreateValueFromAddress(name, self.GetLoadAddress() + offs, mty)


    def IsValid(self):
        """
        SBValue.IsValid() is necessary but not sufficient to check an SBValue is in a valid state.

        'IsValid means this is an SBValue with something in it that wasn't an obvious error, something you might ask questions of.  
        In particular, it's something you can ask GetError().Success() which is the real way to tell if you have an SBValue you should be using.'

        For XNU macros, we always care about whether we have an SBValue we can use - so we overload IsValid() for convenience
        """
        return super().IsValid() and self.error.success

    #
    # Extensions
    #

    def xCreateValueFromAddress(self, name, addr, ty):
        """
        Create an SBValue with the given name by treating the memory starting
        at addr as an entity of type.

        More tolerant wrapper around CreateValueFromAddress() that accepts
        for @c name to be None and @c addr to be an lldb.SBAddress

        @param name (str or None)
            The name of the resultant SBValue

        @param addr (int or lldb.SBAddress)
            The address of the start of the memory region to be used.

        @param ty (lldb.SBType)
            The type to use to interpret the memory starting at addr.

        @return (lldb.SBValue)
            An SBValue of the given type.

        @raises ValueError
            For various error conditions.
        """

        if isinstance(addr, lldb.SBAddress):
            addr = addr.GetLoadAddress()

        if name is None:
            # SBValue's version of CreateValueFromAddress() accepts None,
            # but let's be consistent.
            name = 'newvalue'

        return self.chkCreateValueFromAddress(name, addr, ty)

    def xGetSiblingValueAtIndex(self, index, stride=None):
        """
        Returns a sibling value to the current one in an array.

        This basically performs pointer arithmetics on the SBValue.

        @param index (int)
            The index of the element to return relative to the current one.

        @param stride (int or None):
            If specified, use this stride instead of the natural value type size.

        @returns (lldb.SBValue)
            The resulting value.
        """

        if index:
            addr = self.GetLoadAddress() + index * (stride or self.GetByteSize())
            return self.chkCreateValueFromAddress(self.GetName(), addr, self.GetType())
        return self

    def xIterSiblings(self, start, stop, step=1):
        """
        Returns an iterator for sibling value to the current one in an array.

        This basically performs pointer arithmetics on the SBValue.

        @param start (int)
            The first index (inclusive) to return

        @param stop (int)
            The last index (exclusive) to return

        @param step (int or None):
            The increment step if any

        @returns (lldb.SBValue)
            The resulting value.
        """

        size = self.GetByteSize()
        ty   = self.GetType()
        base = self.GetLoadAddress()

        # aggressively cache the data
        self.target.xReadBytes(base + start * size, (stop - start) * size)

        return (
            self.chkCreateValueFromAddress(None, base + i * size, ty)
            for i in range(start, stop, step)
        )

    def xDereference(self):
        """
        Version of Dereference() that does the right thing for flexible arrays,
        and returns None if NULL is being dereferenced.

        @returns (lldb.SBValue):
            - a reference to value[0] if value is a valid pointer/array
            - None otherwise
        """

        rawty = self.rawGetType()
        fl    = rawty.GetTypeFlags()

        if fl & lldb.eTypeIsArray:
            return self.xCreateValueFromAddress(self.GetName(),
                self.GetLoadAddress(), rawty.GetArrayElementType())

        if fl & lldb.eTypeIsPointer:
            sbv_new = self.GetTarget().xStripPtr(self)
            return sbv_new.chkDereference() if self.GetValueAsAddress() else None

        lldbwrap_raise(TypeError, self.xDereference, "Type can't be dereferenced")


    def xGetValueAsScalar(self, needed=0, rejected=0):
        """
        Get the scalar value of an SBValue

        @param needed (lldb.eTypeIs* mask)
            Sets of flags that should be set or the conversion should fail.

        @param rejected (lldb.eTypeIs* mask)
            Sets of flags that should fail the conversion if set on the value.
        """

        flags = self.rawGetType().GetTypeFlags()

        if (flags & needed) != needed:
            lldbwrap_raise(ValueError, self.xGetValueAsScalar,
                "value of type {} has missing flags {:#x}".format(
                self.GetType().GetDisplayTypeName(), (flags & needed) ^ needed),
                self, needed=needed, rejected=rejected)

        if flags & rejected:
            lldbwrap_raise(ValueError, self.xGetValueAsScalar,
                "value of type {} has rejected flags {:#x}".format(
                self.GetType().GetDisplayTypeName(), flags & rejected),
                self, needed=needed, rejected=rejected)

        if flags & lldb.eTypeIsPointer:
            return self.GetValueAsAddress()

        err = lldb.SBError()
        if flags & lldb.eTypeIsSigned:
            res = self.GetValueAsSigned(err)
        else:
            res = self.GetValueAsUnsigned(err)
            if QUIRK_99785324 and res and flags & lldb.eTypeIsEnumeration:
                try:
                    addr_of = self.rawAddressOf()
                    if (res >> (self.GetByteSize() * 8 - 1) and
                            not (addr_of.IsValid() and addr_of.error.success)):
                        #
                        # This field is:
                        # - likely a bitfield (we can't take its AddressOf())
                        # - unsigned
                        # - with its top bit set
                        #
                        # This might be hitting rdar://99785324 where lldb
                        # incorrectly sign-extends unsigned bit-fields.
                        #
                        # Here comes a crime against good taste: the expression
                        # evaluator of lldb _knows_ how to do the right thing,
                        # and now that the only thing we have is this lousy
                        # lldb.SBValue(), we can only get to it via __str__().
                        #
                        # We parse something like this here:
                        #   '(type_t:12) path = 42'
                        #
                        str_value = str(self)
                        res = int(str_value[str_value.rfind(' '):], 0)
                except:
                    pass

        if res or err.Success():
            return res

        lldbwrap_raise(ValueError, self.xGetValueAsScalar, err.GetCString(),
            self, needed=needed, rejected=rejected)


    def xGetValueAsInteger(self):
        """
        Get the integer value of an SBValue (fails for floats or complex)
        """

        mask = lldb.eTypeIsFloat | lldb.eTypeIsComplex
        return self.xGetValueAsScalar(rejected=mask)


    def xGetValueAsCString(self, max_len=1024):
        """
        Gets the cstring value of an SBValue.

        @param max_len (int)
            The maximum lenght expected for that string

        @returns (str)
            A string holding the contents of the value.

        @raises TypeError
            If the value can't be converted to a string
        """

        if not self.IsValid():
            lldbwrap_raise(ValueError, self.xGetValueAsCString, "Value is invalid", self)

        return self.target.GetProcess().chkReadCStringFromMemory(self.GetValueAsAddress(), max_len)


    def xGetScalarByName(self, name):
        """ same as chkGetChildMemberWithName(name).xGetValueAsScalar() """

        v = self.rawGetChildMemberWithName(name)
        SBValue.xUpcast(v)
        if v.IsValid():
            if QUIRK_100103405:
                v.SetPreferDynamicValue(0)
            return v.xGetValueAsScalar()

        lldbwrap_raise(ValueError, self.GetChildMemberWithName, None, name)

    def xGetScalarAtIndex(self, index):
        """ same as chkGetChildAtIndex(index).xGetValueAsScalar() """

        v = self.GetChildAtIndex(index)
        if v.IsValid():
            if QUIRK_100103405:
                v.SetPreferDynamicValue(0)
            return v.xGetValueAsScalar()

        lldbwrap_raise(ValueError, self.GetChildAtIndex, None, index)

    def xGetScalarByPath(self, path):
        """ same as chkGetValueForExpressionPath(path).xGetValueAsScalar() """

        v = self.rawGetValueForExpressionPath(path)
        SBValue.xUpcast(v)
        if v.IsValid():
            if QUIRK_100103405:
                v.SetPreferDynamicValue(0)
            return v.xGetValueAsScalar()

        lldbwrap_raise(ValueError, self.GetValueForExpressionPath, None, path)


    def xGetIntegerByName(self, name):
        """ same as chkGetChildMemberWithName(name).xGetValueAsInteger() """

        v = self.rawGetChildMemberWithName(name)
        SBValue.xUpcast(v)
        if v.IsValid():
            if QUIRK_100103405:
                v.SetPreferDynamicValue(0)
            return v.xGetValueAsInteger()

        lldbwrap_raise(ValueError, self.GetChildMemberWithName, None, name)

    def xGetIntegerAtIndex(self, index):
        """ same as chkGetChildAtIndex(index).xGetValueAsInteger() """

        v = self.GetChildAtIndex(index)
        if v.IsValid():
            if QUIRK_100103405:
                v.SetPreferDynamicValue(0)
            return v.xGetValueAsInteger()

        lldbwrap_raise(ValueError, self.GetChildAtIndex, None, index)

    def xGetIntegerByPath(self, path):
        """ same as chkGetValueForExpressionPath(path).xGetValueAsInteger() """

        v = self.rawGetValueForExpressionPath(path)
        SBValue.xUpcast(v)
        if v.IsValid():
            if QUIRK_100103405:
                v.SetPreferDynamicValue(0)
            return v.xGetValueAsInteger()

        lldbwrap_raise(ValueError, self.GetValueForExpressionPath, None, path)


    def xGetPointeeByName(self, name):
        """ same as chkGetChildMemberWithName(name).xDereference() """

        v = self.rawGetChildMemberWithName(name)
        SBValue.xUpcast(v)
        if v.IsValid():
            return v.xDereference()

        lldbwrap_raise(ValueError, self.GetChildMemberWithName, None, name)

    def xGetPointeeAtIndex(self, index):
        """ same as chkGetChildAtIndex(index).xDereference() """

        v = self.GetChildAtIndex(index)
        if v.IsValid():
            return v.xDereference()

        lldbwrap_raise(ValueError, self.GetChildAtIndex, None, index)

    def xGetPointeeByPath(self, path):
        """ same as chkGetValueForExpressionPath(path).xDereference() """

        v = self.rawGetValueForExpressionPath(path)
        SBValue.xUpcast(v)
        if v.IsValid():
            return v.xDereference()

        lldbwrap_raise(ValueError, self.GetValueForExpressionPath, None, path)


    def xGetLoadAddressByName(self, name):
        """ same as chkGetChildMemberWithName(name).GetLoadAddress() """

        v = self.rawGetChildMemberWithName(name)
        SBValue.xUpcast(v)
        if v.IsValid():
            if QUIRK_100103405:
                v.SetPreferDynamicValue(0)
            return v.GetLoadAddress()

        lldbwrap_raise(ValueError, self.GetChildMemberWithName, None, name)

    def xGetLoadAddressAtIndex(self, index):
        """ same as chkGetChildAtIndex(index).GetLoadAddress() """

        v = self.GetChildAtIndex(index)
        if v.IsValid():
            if QUIRK_100103405:
                v.SetPreferDynamicValue(0)
            return v.GetLoadAddress()

        lldbwrap_raise(ValueError, self.GetChildAtIndex, None, index)

    def xGetLoadAddressByPath(self, path):
        """ same as chkGetValueForExpressionPath(path).GetLoadAddress() """

        v = self.rawGetValueForExpressionPath(path)
        SBValue.xUpcast(v)
        if v.IsValid():
            if QUIRK_100103405:
                v.SetPreferDynamicValue(0)
            return v.GetLoadAddress()

        lldbwrap_raise(ValueError, self.GetValueForExpressionPath, None, path)


    def xGetCStringByName(self, name, *args):
        """ same as chkGetChildMemberWithName(name).xGetValueAsCString() """

        v = self.rawGetChildMemberWithName(name)
        SBValue.xUpcast(v)
        if v.IsValid():
            if QUIRK_100103405:
                v.SetPreferDynamicValue(0)
            return v.xGetValueAsCString(*args)

        lldbwrap_raise(ValueError, self.GetChildMemberWithName, None, name)

    def xGetCStringAtIndex(self, index, *args):
        """ same as chkGetChildAtIndex(index).xGetValueAsCString() """

        v = self.GetChildAtIndex(index)
        if v.IsValid():
            if QUIRK_100103405:
                v.SetPreferDynamicValue(0)
            return v.xGetValueAsCString(*args)

        lldbwrap_raise(ValueError, self.GetChildAtIndex, None, index)

    def xGetCStringByPath(self, path, *args):
        """ same as chkGetValueForExpressionPath(path).xGetValueAsCString() """

        v = self.rawGetValueForExpressionPath(path)
        SBValue.xUpcast(v)
        if v.IsValid():
            if QUIRK_100103405:
                v.SetPreferDynamicValue(0)
            return v.xGetValueAsCString(*args)

        lldbwrap_raise(ValueError, self.GetValueForExpressionPath, None, path)


def GetDebugger():
    """ Alternative to lldb.debugger since we can't hook globals """
    return SBDebugger(lldb.debugger)

def GetTarget():
    """
    Alternative to lldb.target

    Using lldb.target has several issues because it is set late by lldb,
    and might resolve to None even when there is a selected target already.
    """

    return GetDebugger().GetSelectedTarget()

def GetProcess():
    """
    Alternative to lldb.process

    Using lldb.process has several issues because it is set late by lldb,
    and might resolve to None even when there is a selected target already.
    """
    return GetTarget().GetProcess()

__all__.extend((
    GetDebugger.__name__,
    GetProcess.__name__,
    GetTarget.__name__,
))


################################################################################
#
# Code to generate the module content by replicating `lldb`
#

def lldbwrap_generate(this_module):
    sb_classes = (
       m
       for m in inspect.getmembers(lldb, inspect.isclass)
       if m[0][:2] == "SB"
    )

    for name, base in sb_classes:
        cls = getattr(this_module, name, None)
        if not hasattr(this_module, name):
            attr = {}
            lldbwrap_update_class_dict(name, base, attr)
            cls = type(name, (base,), attr)
            setattr(this_module, name, cls)

        UPCASTS[base] = cls.xUpcast
        __all__.append(name)

    #
    # Re-export globals
    #

    for name, value in inspect.getmembers(lldb):

        if name.startswith("LLDB_"):
            setattr(this_module, name, value)
            __all__.append(name)
            continue

        if name[0] == 'e' and name[1].isupper():
            setattr(this_module, name, value)
            __all__.append(name)
            continue

lldbwrap_generate(sys.modules[__name__])
