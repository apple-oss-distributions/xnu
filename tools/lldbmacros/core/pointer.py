"""
Custom pointer support

This module provides support for special pointer types that are not native to the
language used by the target being debugged. Such pointers may be represented as a struct
or class (for example IOKit's shared pointers).

A custom pointer class must subclass the PointerPolicy class and implement all of its
abstract methods. The MetaPointerPolicy metaclass ensures that all known subclasses are
registered in a global list (wherever they are located in the lldb macro sources).

A client can obtain a PointerPolicy instance by calling the match method with an SBValue
instance as an argument. The returned value is one of:

    * None - the match was unsuccessful and this SBValue instance is not a pointer.
    * Concrete instance - An instance of the concrete PointerPolicy class that will handle
      pointer operations for the given SBValue.

Concrete policy instances implement an API that allows a client to operate on a value
like a native pointer (for example unwrapping a native pointer from a smart pointer).

Example:

    # Obtain an SBValue instance.
    val = kern.global.GlobalVariable.GetSBValue()

    # Try to match the pointer policy for the given value.
    policy = PointerPolicy.match(val)

    # Unwrap the pointer SBValue.
    if policy:
        val = policy.GetPointerSBValue(val)

    ... Operate on val as usual.
"""
from operator import methodcaller
from abc import ABCMeta, abstractmethod

import lldb

from .caching import cache_statically


class MetaPointerPolicy(ABCMeta):
    """ Register a custom pointer policy in global list. """

    classes = []

    def __new__(cls, clsname, bases, args):
        newcls = super(MetaPointerPolicy, cls).__new__(cls, clsname, bases, args)
        cls.classes.append(newcls)
        return newcls


class Singleton(MetaPointerPolicy):
    """ Meta class for creation of singleton instances. """

    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class PointerPolicy(object, metaclass=ABCMeta):
    """ Abstract base class common to every custom pointer policy. """

    @classmethod
    def match(cls, sbvalue):
        """ Match pointer representation based on given SBValue. """
        matching = filter(bool, map(methodcaller('match', sbvalue), MetaPointerPolicy.classes))
        return next(matching, None)

    @abstractmethod
    def GetPointerSBValue(self, sbvalue):
        """ Returns pointer value that debugger should operate on. """


# Pointers need to have their TBI byte stripped if in use. TBI KASan,
# for instance, tags pointers to detect improper memory accesses. Reading
# values from such tagged pointers fails.
#
# Stripping the pointers requires to learn whether TBI is in use or not.
# We do that by checking presence of 'kasan_tbi_enabled' symbol which only
# exists on the TBI KASan variant. Since KASan is one of more TBI
# consumers (along with PAC or Sandbox) this is not an ideal approach.
# Inspecting respective CPU state would be more appropriate.


class NativePointer(PointerPolicy, metaclass=Singleton):
    """ Policy for native pointers.

        Strips top bits of a pointer if TBI is in use. Otherwise
        pointer is used as-is.

        Native pointers do not have any per-pointer attributes so this policy
        can be singleton instance.
    """

    @staticmethod
    @cache_statically
    def isTagged(target=None):
        """ Pointer stripping isn't required as of recent lldb changes that fixed ignoring
        non-addresable bits.
        Due to performance degredation on relevant coredumps, stripping is being
        as a quick remedy.
        Depending on future debugging needs, it'll be removed completely, or improved
        to have acceptable performance.
        """
        is_tagged = False

        """ Returns true on TBI KASan targets, false otherwise. """
        # is_tagged = target.FindFirstGlobalVariable('kasan_tbi_enabled').IsValid()
        return is_tagged

    def __init__(self):
        if self.isTagged():
            self._stripPtr = self.stripPtr
        else:
            self._stripPtr = lambda val: val

    @classmethod
    def match(cls, sbvalue):
        return cls() if sbvalue.GetType().IsPointerType() else None

    @staticmethod
    def stripPtr(sbvalue: lldb.SBValue):
        """ Strips the TBI byte value. Since the value is not a plain value but
            represents a value of a variable, a register or an expression the
            conversion is performed by (re-)creating the value through expression.
        """
        if sbvalue.GetValueAsAddress() != sbvalue.GetValueAsUnsigned():
            addr = sbvalue.GetValueAsAddress()
            sbv_new = sbvalue.CreateValueFromExpression(None, '(void *)' + str(addr))
            return sbv_new.Cast(sbvalue.GetType())

        return sbvalue

    def GetPointerSBValue(self, sbvalue):
        return self._stripPtr(sbvalue)
