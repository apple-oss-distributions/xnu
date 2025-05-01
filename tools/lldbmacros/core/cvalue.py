"""
Defines a class value which encapsulates the basic lldb Scripting Bridge APIs. This provides an easy
wrapper to extract information from C based constructs.

 |------- core.value------------|
 | |--lldb Scripting Bridge--|  |
 | |    |--lldb core--|      |  |
 | |-------------------------|  |
 |------------------------------|

Use the member function GetSBValue() to access the base Scripting Bridge value.
"""
import contextlib
# The value class is designed to be Python 2/3 compatible. Pulling in more
# builtins classes may break it.
import numbers
from typing import Optional

import lldb
import re
from .caching import (
    cache_statically,
)
from .pointer import PointerPolicy

_CSTRING_REX = re.compile(r"((?:\s*|const\s+)\s*char(?:\s+\*|\s+[A-Za-z_0-9]*\s*\[|)\s*)", re.MULTILINE | re.DOTALL)


# pragma pylint: disable=hex-method, div-method, rdiv-method, idiv-method, oct-method, nonzero-method
class value(object):
    """A class designed to wrap lldb.SBValue() objects so the resulting object
    can be used as a variable would be in code. So if you have a Point structure
    variable in your code in the current frame named "pt", you can initialize an instance
    of this class with it:

    pt = lldb.value(lldb.frame.FindVariable("pt"))
    print pt
    print pt.x
    print pt.y

    pt = lldb.value(lldb.frame.FindVariable("rectangle_array"))
    print rectangle_array[12]
    print rectangle_array[5].origin.x
    """

    __slots__ = ('__sbval', '__ptr')

    def __init__(self, sbvalue, usePtrPolicy=True):
        # Using a double `__` means this will be hidden from getattr()
        # and can't conflict with C/C++ type field names.
        self.__sbval = sbvalue
        self.__ptr = PointerPolicy.match(sbvalue) if usePtrPolicy else None

    @property
    def sbvalue(self):
        """backward compability for the old .sbvalue property"""
        return self.GetSBValue()

    @property
    def ptrpolicy(self):
        return self.__ptr

    @ptrpolicy.setter
    def ptrpolicy(self, policy):
        self.__ptr = policy

    def __bool__(self):
        return self.__sbval.__bool__() and self._GetValueAsUnsigned() != 0

    def __nonzero__(self):
        return self.__sbval.__nonzero__() and self._GetValueAsUnsigned() != 0

    def __repr__(self):
        return self.__sbval.__str__()

    #
    # Compare operators
    #

    def __eq__(self, other):
        if isinstance(other, value):
            self_val = self._GetValueAsUnsigned()
            other_val = other._GetValueAsUnsigned()
            return self_val == other_val
        if isinstance(other, numbers.Integral):
            return int(self) == other
        raise TypeError("EQ operator is not defined for this type.")

    def __ne__(self, other):
        return not self == other

    def __lt__(self, other):
        if isinstance(other, value):
            self_val = self._GetValueAsUnsigned()
            other_val = other._GetValueAsUnsigned()
            return self_val < other_val
        if isinstance(other, numbers.Integral):
            return int(self) < int(other)
        raise TypeError("LT operator is not defined for this type")

    def __le__(self, other):
        return self < other or self == other

    def __gt__(self, other):
        return not self <= other

    def __ge__(self, other):
        return not self < other

    def __str__(self):
        global _CSTRING_REX
        sbv = self.__sbval
        type_name = sbv.GetType().GetCanonicalType().GetName()
        if len(_CSTRING_REX.findall(type_name)) > 0:
            return self._GetValueAsString()
        summary = sbv.GetSummary()
        if summary:
            return summary.strip('"')
        return sbv.__str__()

    def __getitem__(self, key):
        # Allow array access if this value has children...
        if type(key) is slice:
            _start = int(key.start)
            _end = int(key.stop)
            _step = 1
            if key.step is not None:
                _step = int(key.step)
            retval = []
            while _start < _end:
                retval.append(self[_start])
                _start += _step
            return retval
        if type(key) is value:
            key = int(key)
        if isinstance(key, numbers.Integral):
            sbv = self.__sbval
            if self.__ptr:
                sbv = self.__ptr.GetPointerSBValue(sbv)
            child_sbvalue = sbv.GetValueForExpressionPath("[%i]" % key)
            if child_sbvalue and child_sbvalue.IsValid():
                return value(child_sbvalue)
            raise IndexError("Index '%d' is out of range" % key)
        raise TypeError("Cannot fetch array item for key of type {}".format(str(type(key))))

    def __getattr__(self, name):
        sbv = self.__sbval
        if self.__ptr:
            sbv = self.__ptr.GetPointerSBValue(sbv)
        child_sbvalue = sbv.GetChildMemberWithName(name)
        if child_sbvalue and child_sbvalue.IsValid():
            return value(child_sbvalue)
        raise AttributeError("No field by name: " + name)

    def __add__(self, other):
        return int(self) + int(other)

    def __radd__(self, other):
        return int(self) + int(other)

    def __sub__(self, other):
        return int(self) - int(other)

    def __rsub__(self, other):
        return int(other) - int(self)

    def __mul__(self, other):
        return int(self) * int(other)

    def __rmul__(self, other):
        return int(self) * int(other)

    def __floordiv__(self, other):
        return int(self) // int(other)

    def __rfloordiv__(self, other):
        return int(other) // int(self)

    def __mod__(self, other):
        return int(self) % int(other)

    def __rmod__(self, other):
        return int(other) % int(self)

    def __divmod__(self, other):
        return divmod(int(self), int(other))

    def __rdivmod__(self, other):
        return divmod(int(other), int(self))

    def __pow__(self, other):
        return int(self) ** int(other)

    def __lshift__(self, other):
        return int(self) << int(other)

    def __rshift__(self, other):
        return int(self) >> int(other)

    def __and__(self, other):
        return int(self) & int(other)

    def __rand__(self, other):
        return int(other) & int(self)

    def __xor__(self, other):
        return int(self) ^ int(other)

    def __or__(self, other):
        return int(self) | int(other)

    def __truediv__(self, other):
        return int(self) / int(other)

    def __rtruediv__(self, other):
        return int(other) / int(self)

    def __iadd__(self, other):
        result = self.__add__(other)
        self.__sbval.SetValueFromCString(str(result))
        return result

    def __isub__(self, other):
        result = self.__sub__(other)
        self.__sbval.SetValueFromCString(str(result))
        return result

    def __imul__(self, other):
        result = self.__mul__(other)
        self.__sbval.SetValueFromCString(str(result))
        return result

    def __idiv__(self, other):
        result = self.__div__(other)
        self.__sbval.SetValueFromCString(str(result))
        return result

    def __itruediv__(self, other):
        result = self.__truediv__(other)
        self.__sbval.SetValueFromCString(str(result))
        return result

    def __ifloordiv__(self, other):
        result = self.__floordiv__(other)
        self.__sbval.SetValueFromCString(str(result))
        return result

    def __imod__(self, other):
        result = self.__mod__(other)
        self.__sbval.SetValueFromCString(str(result))
        return result

    def __ipow__(self, other):
        result = self.__pow__(other)
        self.__sbval.SetValueFromCString(str(result))
        return result

    def __ilshift__(self, other):
        result = self.__lshift__(other)
        self.__sbval.SetValueFromCString(str(result))
        return result

    def __irshift__(self, other):
        result = self.__rshift__(other)
        self.__sbval.SetValueFromCString(str(result))
        return result

    def __iand__(self, other):
        result = self.__and__(other)
        self.__sbval.SetValueFromCString(str(result))
        return result

    def __ixor__(self, other):
        result = self.__xor__(other)
        self.__sbval.SetValueFromCString(str(result))
        return result

    def __ior__(self, other):
        result = self.__or__(other)
        self.__sbval.SetValueFromCString(str(result))
        return result

    def __neg__(self):
        return -int(self)

    def __pos__(self):
        return +int(self)

    def __abs__(self):
        return abs(int(self))

    def __invert__(self):
        return ~int(self)

    def __complex__(self):
        return complex(int(self))

    def __int__(self):
        sbv = self.__sbval
        if self.__ptr:
            sbv = self.__ptr.GetPointerSBValue(sbv)

        flags = sbv.GetType().GetTypeFlags()
        if flags & lldb.eTypeIsPointer:
            return sbv.GetValueAsAddress()
        if not flags & lldb.eTypeIsSigned:
            return self._GetValueAsUnsigned()

        return sbv.GetValueAsSigned()

    # Python 3 conversion to int calls this.
    def __index__(self):
        return self.__int__()

    def __long__(self):
        sbv = self.__sbval
        if self.__ptr:
            sbv = self.__ptr.GetPointerSBValue(sbv)

        flags = sbv.GetType().GetTypeFlags()
        if flags & lldb.eTypeIsPointer:
            return sbv.GetValueAsAddress()
        if not flags & lldb.eTypeIsSigned:
            return self._GetValueAsUnsigned()

        return sbv.GetValueAsSigned()

    def __float__(self):
        return float(self.__sbval.GetValueAsSigned())

    # Python 2 must return native string.
    def __oct__(self):
        return '0%o' % self._GetValueAsUnsigned()

    # Python 2 must return native string.
    def __hex__(self):
        return '0x%x' % self._GetValueAsUnsigned()

    def __hash__(self):
        return hash(self.__sbval)

    def GetRawSBValue(self):
        return self.__sbval

    def GetSBValue(self):
        sbv = self.__sbval
        if self.__ptr:
            sbv = self.__ptr.GetPointerSBValue(sbv)

        return sbv

    def __getstate__(self):
        err = lldb.SBError()
        sbv = self.__sbval
        if self.__ptr:
            sbv = self.__ptr.GetPointerSBValue(sbv)
            addr = sbv.GetValueAsAddress()
            size = sbv.GetType().GetPointeeType().GetByteSize()
        else:
            addr = sbv.GetLoadAddress()
            size = sbv.GetType().GetByteSize()

        content = sbv.GetProcess().ReadMemory(addr, size, err)
        if err.fail:
            content = ''
        return content

    def _GetValueAsSigned(self):
        sbv = self.__sbval
        if self.__ptr:
            print("ERROR: You cannot get 'int' from pointer type %s, please use unsigned(obj) for such purposes." % sbv.GetType().GetDisplayTypeName())
            raise ValueError("Cannot get signed int for pointer data.")
        serr = lldb.SBError()
        retval = sbv.GetValueAsSigned(serr)
        if serr.success:
            return retval
        raise ValueError("Failed to read signed data. {} (type = {}) Error description: {}".format(
            str(sbv), sbv.GetType().GetDisplayTypeName(), serr.GetCString()))

    def _GetValueAsCast(self, dest_type):
        if not isinstance(dest_type, lldb.SBType):
            raise ValueError("Invalid type for dest_type: {}".format(type(dest_type)))
        val = value(self.__sbval.Cast(dest_type))
        return val

    def _GetValueAsUnsigned(self):
        sbv = self.__sbval
        if self.__ptr:
            sbv = self.__ptr.GetPointerSBValue(sbv)
            return sbv.GetValueAsAddress()
        serr = lldb.SBError()
        retval = sbv.GetValueAsUnsigned(serr)
        if serr.success:
            return retval
        raise ValueError("Failed to read unsigned data. {} (type = {}) Error description: {}".format(
            str(sbv), sbv.GetType().GetDisplayTypeName(), serr.GetCString()))

    def _GetValueAsString(self, offset=0, maxlen=1024):
        sbv = self.__sbval
        serr = lldb.SBError()
        sbdata = None
        if self.__ptr:
            sbv = self.__ptr.GetPointerSBValue(sbv)
            sbdata = sbv.GetPointeeData(offset, maxlen)
        else:
            sbdata = sbv.GetData()

        retval = ''
        bytesize = sbdata.GetByteSize()
        if bytesize == 0:
            # raise ValueError('Unable to read value as string')
            return ''
        for i in range(0, bytesize):
            serr.Clear()
            ch = chr(sbdata.GetUnsignedInt8(serr, i))
            if serr.fail:
                raise ValueError("Unable to read string data: " + serr.GetCString())
            if ch == '\0':
                break
            retval += ch
        return retval

    def __format__(self, format_spec):
        # typechar is last char. see http://www.python.org/dev/peps/pep-3101/
        typechar = format_spec[-1] if len(format_spec) else ''

        if typechar in 'bcdoxX': # requires integral conversion
            return format(int(self), format_spec)

        if typechar in 'eEfFgG%': # requires float conversion
            return format(float(self), format_spec)

        if typechar in 's': # requires string conversion
            return format(str(self), format_spec)

        # 'n' or '' mean "whatever you got for me"
        flags = self.__sbval.GetType().GetTypeFlags()
        if flags & lldb.eTypeIsFloat:
            return format(float(self), format_spec)
        elif flags & lldb.eTypeIsScalar:
            return format(int(self), format_spec)
        else:
            return format(str(self), format_spec)

def unsigned(val):
    """ Helper function to get unsigned value from core.value
        params: val - value (see value class above) representation of an integer type
        returns: int which is unsigned.
        raises : ValueError if the type cannot be represented as unsigned int.
    """
    if type(val) is value:
        return int(val._GetValueAsUnsigned())
    return int(val)


def signed(val):
    """ Helper function to get signed value from core.value
        params: val - value (see value class above) representation of an integer type
        returns: int which is signed.
        raises: ValueError if the type cannot be represented as signed int.
    """
    if type(val) is value:
        return val.GetSBValue().GetValueAsSigned()
    return int(val)


def sizeof(t):
    """ Find the byte size of a type.
        params: t - str : ex 'time_spec' returns equivalent of sizeof(time_spec) in C
                t - value: ex a value object. returns size of the object
        returns: int - byte size length
    """
    if type(t) is value:
        return t.GetSBValue().GetByteSize()
    if isinstance(t, str):
        return gettype(t).GetByteSize()
    raise ValueError("Cannot get sizeof. Invalid argument")


def dereference(val):
    """ Get a dereferenced obj for a pointer type obj
        params: val - value object representing a pointer type C construct in lldb
        returns: value - value
        ex. val = dereference(ptr_obj) #python
        is same as
            obj_ptr = (int *)0x1234  #C
            val = *obj_ptr           #C
    """
    if type(val) is value:
        sbv = val.GetSBValue()
        return value(sbv.Dereference())
    raise TypeError('Cannot dereference this type.')


def wrapped(val):
    """ Get original pointer value without aplying pointer policy.
        param: val - value object representing a pointer
        returns: value - value
    """
    if isinstance(val, value):
        policy = val.ptrpolicy
        val.ptrpolicy = None
        newval = value(val.GetSBValue(), False)
        val.ptrpolicy = policy
        return newval
    raise TypeError("Cannot do wrapped for non-value type objects")


def addressof(val):
    """ Get address of a core.value object.
        params: val - value object representing a C construct in lldb
        returns: value - value object referring to 'type(val) *' type
        ex. addr = addressof(hello_obj)  #python
        is same as
           uintptr_t addr = (uintptr_t)&hello_obj  #C
    """
    if type(val) is value:
        return value(val.GetSBValue().AddressOf())
    raise TypeError("Cannot do addressof for non-value type objects")


def cast(obj, target_type):
    """ Type cast an object to another C type.
        params:
            obj - core.value  object representing some C construct in lldb
            target_type - str : ex 'char *'
                        - lldb.SBType :
    """
    dest_type = target_type
    if isinstance(target_type, str):
        dest_type = gettype(target_type)
    elif type(target_type) is value:
        dest_type = target_type.GetSBValue().GetType()

    if type(obj) is value:
        return obj._GetValueAsCast(dest_type)
    elif type(obj) is int:
        print("ERROR: You cannot cast an 'int' to %s, please use kern.GetValueFromAddress() for such purposes." % str(target_type))
    raise TypeError("object of type %s cannot be casted to %s" % (str(type(obj)), str(target_type)))

def containerof(obj, target_type, field_name):
    """ Type cast an object to another C type from a pointer to a field.
        params:
            obj - core.value  object representing some C construct in lldb
            target_type - str : ex 'struct thread'
                        - lldb.SBType :
            field_name - the field name within the target_type obj is a pointer to
    """
    addr = int(obj) - getfieldoffset(target_type, field_name)
    sbv  = obj.GetSBValue()
    sbv  = sbv.chkCreateValueFromAddress(None, addr, gettype(target_type))
    return value(sbv.AddressOf())


@cache_statically
def gettype(target_type, target=None):
    """ Returns lldb.SBType of the given target_type
        params:
            target_type - str, ex. 'char', 'uint32_t' etc
        returns:
            lldb.SBType - SBType corresponding to the given target_type
        raises:
            NameError  - Incase the type is not identified
    """

    #
    # If the type was qualified with a `struct` or `class`, ...
    # make sure we pick up the proper definition in case of clashes.
    #
    want = 0
    name = str(target_type).strip()

    if name.startswith("struct"):
        want = lldb.eTypeClassStruct
    elif name.startswith("union"):
        want = lldb.eTypeClassUnion
    elif name.startswith("class"):
        want = lldb.eTypeClassClass
    elif name.startswith("enum"):
        want = lldb.eTypeClassEnumeration
    elif name.startswith("typedef"):
        want = lldb.eTypeClassTypedef

    #
    # Now remove constness and speficiers, and pointers
    #
    tmpname  = re.sub(r'\bconst\b', '', name).strip(" ")
    tmpname  = re.sub(r'^(struct|class|union|enum|typedef) ', '', tmpname)
    basename = tmpname.rstrip(" *")
    ptrlevel = tmpname.count('*', len(basename))

    def resolve_pointee_type(t: lldb.SBType):
        while t.IsPointerType():
            t = t.GetPointeeType()
        return t

    def type_sort_heuristic(t: lldb.SBType) -> int:
        """ prioritizes types with more fields, and prefers fields with complete
        types
            params:
                t - lldb.SBType, type to score
            returns:
                int - heuristic score
        """
        # we care about the underlying type, not the pointer
        resolved_type: lldb.SBType = resolve_pointee_type(t)
        
        # heuristic score
        score = 0
        for field in resolved_type.fields:
            resolved_field_type = resolve_pointee_type(field.GetType())
            score += 3 if resolved_field_type.IsTypeComplete() else 1

        return score

    type_arr = [t for t in target.chkFindTypes(basename)]
    # After the sort, the best matching struct will be at index [0].
    # This heuristic selects a struct type with more fields (with complete types)
    # compared to ones with "opaque" members
    type_arr.sort(reverse=True, key=type_sort_heuristic)

    for tyobj in type_arr:
        if want and tyobj.GetTypeClass() != want:
            continue

        for _ in range(ptrlevel):
            tyobj = tyobj.GetPointerType()

        return tyobj

    raise NameError('Unable to find type {}'.format(target_type))


@cache_statically
def getfieldoffset(struct_type, field_name_or_path, target=None):
    """ Returns the byte offset of a field inside a given struct
        Understands anonymous unions and field names in sub-structs
        params:
            field_name_or_path  - str, name or path to the field inside the struct ex. 'ip_messages'
        returns:
            int - byte offset of the field_name inside the struct_type
    """

    return gettype(struct_type).xGetFieldOffset(field_name_or_path)


def islong(x):
    """ Returns True if a string represents a long integer, False otherwise
    """
    try:
        int(x, 16)
    except ValueError:
        try:
            int(x)
        except ValueError:
            return False
    return True


def readmemory(val):
    """ Returns a string of hex data that is referenced by the value.
        params: val - a value object.
        return: str - string of hex bytes.
        raises: TypeError if val is not a valid type
    """
    if not type(val) is value:
        raise TypeError('%s is not of type value' % str(type(val)))
    return val.__getstate__()


def getOSPtr(cpp_obj):
    """ Returns a core.value created from an intrusive_shared_ptr or itself, cpp_obj
        params: cpp_obj - core.value object representing a C construct in lldb
        return: core.value - newly created core.value or cpp_obj
    """
    child = cpp_obj.GetSBValue().GetChildAtIndex(0)
    if 'intrusive_shared_ptr' in str(child):
        return value(child.GetChildMemberWithName('ptr_'))
    return cpp_obj


def get_field(val: value, field: str) -> Optional[value]:
    """
    Attempts getting a value's field.
    Returns None (suppressing the exception) in case of failure
    """
    with contextlib.suppress(AttributeError):
        return val.__getattr__(field)
    return None