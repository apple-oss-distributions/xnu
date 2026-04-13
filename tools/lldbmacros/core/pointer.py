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


class NativePointer(PointerPolicy, metaclass=Singleton):
    """ Policy for native pointers.

        Native pointers do not have any per-pointer attributes so this policy
        can be singleton instance.
    """

    @classmethod
    def match(cls, sbvalue):
        return cls() if sbvalue.GetType().IsPointerType() else None

    def GetPointerSBValue(self, sbvalue):
        return sbvalue
