import operator

from abc import ABCMeta, abstractmethod
from core import (
    caching,
    gettype,
)

from .kmem import KMem, MemoryRange


class MemoryObject(object, metaclass=ABCMeta):
    """
    Abstract class for any memory object resolved by Whatis
    """

    MO_KIND = None

    def __init__(self, kmem, address):
        self.kmem    = kmem
        self.address = address

    @property
    @abstractmethod
    def object_range(self):
        """
        Returns the MemoryRange for this object if any
        """
        pass

    @abstractmethod
    def describe(self, verbose=False):
        """
        Method to describe oneself for whatis
        """
        pass


class UnknownMemoryObject(MemoryObject):
    """ Fallback Memory Object for unclaimed addresses """

    MO_KIND = "<unknown>"

    @property
    def object_range(self):
        return None

    def describe(self, verbose=False):
        print("Unknown Memory Object Info")
        print(" this address is not recognized, please implement/extend")
        print(" a WhatisProvider to recognize it in the future")
        print()


class WhatisProvider(object):
    """ Base class for Whatis Providers """

    """
    List of direct subclasses, used for resolution
    """
    subproviders = []

    """
    Evaluation cost of this provider

    the higher the cost, the later it gets evaluated.
    """

    COST = 10

    def __init__(self, target):
        self._children = list(cls(target) for cls in self.__class__.subproviders)
        self.kmem      = KMem.get_shared()
        self.target    = target

    @staticmethod
    @caching.cache_statically
    def get_shared(target=None):
        return WhatisProvider(target)

    def find_provider(self, address):
        return next(iter(c for c in self._children if c.claims(address)), self)

    def claims(self, address):
        """
        Returns whether this provider "claims" the address

        @param address (int)
            The addrress being considered
        """

        pass

    def lookup(self, address):
        """
        Lookup a memory object by address

        @param address (int)
            The addrress being considered

        @returns (MemoryObject)
        """

        return UnknownMemoryObject(self.kmem, address)

    def describe(self, mo):
        """
        Describe a memory object

        Providers can override this method to add more information.
        """

        print((
            "Basic Info\n"
            " kind                 : {0.__class__.MO_KIND}\n"
            " address              : {0.address:#x}"
        ).format(mo))

        mem_r = mo.object_range
        if mem_r is None:
            print(" {:<21s}: Unknown".format("object range"))
        else:
            print(" {:<21s}: {r.start:#x} - {r.end:#x} ({r.size:,d} bytes)".format(
                "object range", r = mem_r))
            address = mo.address
            if address != mem_r.start:
                print(" {:<21s}: {:,d} from start, {:,d} to end".format(
                    "offset", address - mem_r.start, mem_r.end - address))

        print()


def whatis_provider(cls):
    """
    Class decorator for Whatis providers
    """

    if not issubclass(cls, WhatisProvider):
        raise TypeError("{} is not a subclass of WhatisProvider".format(cls.__name__))

    cls.subproviders = []
    base = cls.__base__

    if base != object:
        k = next((
            k for k in ['claims', 'lookup']
            if getattr(cls, k) == getattr(base, k)
        ), None)
        if k:
            raise TypeError("{} must reimplement function '{}'".format(cls.__name__, k))

        base.subproviders.append(cls)
        base.subproviders.sort(key=operator.attrgetter('COST'))

    return cls


__all__ = [
    whatis_provider.__name__,

    MemoryObject.__name__,
    WhatisProvider.__name__,
]
