from abc import (
    ABCMeta,
    abstractmethod,
    abstractproperty,
)
import argparse
import re
import struct
from typing import (
    Optional,
)

from core import (
    SBValueFormatter,
    caching,
    gettype,
    lldbwrap,
    value,
    xnu_format,
)
from core.standard import (
    ArgumentError,
)
from core.kernelcore import (
    KernelTarget,
)
from core.iterators import (
    RB_HEAD,
)

from .kmem   import MemoryRange
from .btlog  import BTLog, BTLibrary
from .whatis import *

# FIXME: should not import this from xnu / utils
from pmap import (
    PmapWalkARM64,
    PmapWalkX86_64,
    KVToPhysARM,
)
from utils import (
    GetEnumName,
    print_hex_data,
)
from xnu import (
    lldb_command,
)

@SBValueFormatter.converter("vm_prot")
def vm_prot_converter(prot):
    PROT_STR = "-rw?x"
    return PROT_STR[prot & 1] + PROT_STR[prot & 2] + PROT_STR[prot & 4]


class Pmap(object, metaclass=ABCMeta):
    """ Helper class to manipulate a pmap_t"""

    def __new__(cls, pmap: lldbwrap.SBValue, name: Optional[str]=None):
        target = pmap.GetTarget()
        arch   = target.triple[:target.triple.find('-')]

        if cls is Pmap:
            if arch.startswith('arm64'):
                return _PmapARM64(pmap, name)
            elif arch.startswith('x86_64'):
                return _PmapX86(pmap, name)
            else:
                return None

        return super(Pmap, cls).__new__(cls)

    def __init__(self, pmap: lldbwrap.SBValue, name: Optional[str]=None):
        self.sbv       = pmap
        self.name      = name
        self.kern      = KernelTarget(pmap.GetTarget().GetDebugger())
        self.page_size = 4096

        self._last_phytokv_paddr = None
        self._last_phytokv_result = None

    def describe(self, verbose=False):
        fmt = (
            "Pmap Info\n"
            " pmap                 : {&v:#x} \n"
        )

    @staticmethod
    @caching.cache_statically
    def kernel_pmap(target=None):
        """
        Returns an object for the kernel pmap
        """

        pmap = target.FindFirstGlobalVariable('kernel_pmap').Dereference()
        return Pmap(pmap, 'kernel_pmap')

    def phystokv(self, paddr: int) -> int:
        base = self.trunc_page(paddr)

        if self._last_phytokv_paddr != base:
            self._last_phytokv_paddr = base
            self._last_phytokv_result = self.kern.PhysToKernelVirt(base)

        return self._last_phytokv_result + self.page_offset(paddr)

    def trunc_page(self, addr: int) -> int:
        return addr & -self.page_size

    def round_page(self, addr: int) -> int:
        return (addr + self.page_size - 1) & -self.page_size

    def page_offset(self, addr: int) -> int:
        return addr & (self.page_size - 1)

    @abstractmethod
    def kvtophys(self, vaddr: int) -> int:
        """
        resolves a kernel virtual address into a physical address
        """
        pass

    @abstractmethod
    def walk(self, vaddr: int, extra: Optional[dict] = None) -> Optional[int]:
        """
        resolves a virtual address to a physical address for this pmap

        @param vaddr (int)
            The address to resolve

        @param extra (dict)
            Extra pmap specific information about the mapping
        """

        pass


class _PmapARM64(Pmap):
    """
    Specialization of Pmap for arm64
    """

    def __init__(self, pmap: lldbwrap.SBValue, name: Optional[str]=None):
        super().__init__(pmap, name)

        target = pmap.GetTarget()
        self.gVirtBase = target.FindFirstGlobalVariable('gVirtBase').xGetValueAsInteger()
        self.gPhysBase = target.FindFirstGlobalVariable('gPhysBase').xGetValueAsInteger()

        try:
            self.pt_attr = pmap.chkGetChildMemberWithName('pmap_pt_attr')
        except:
            self.pt_attr = target.FindFirstGlobalVariable('native_pt_attr')
        self.page_size = self.pt_attr.xGetIntegerByName('pta_page_size')


        self._last_walk_vaddr = None
        self._last_walk_extra = None
        self._last_walk_result = None

        self._last_kvtophys_vaddr = None
        self._last_kvtophys_result = None

    def kvtophys(self, vaddr: int) -> int:
        base = self.trunc_page(vaddr)

        if self._last_kvtophys_vaddr != base:
            self._last_walk_vaddr = base
            self._last_walk_result = KVToPhysARM(base)

        return self._last_walk_result + self.page_offset(base)

    def walk(self, vaddr: int, extra: Optional[dict] = None) -> Optional[int]:
        base = self.trunc_page(vaddr)

        if self._last_walk_vaddr != base:
            self._last_walk_vaddr = base
            self._last_walk_extra = {}

            tte = self.sbv.chkGetChildMemberWithName('tte')
            self._last_walk_result = PmapWalkARM64(
                value(self.pt_attr), value(tte), base,
                0, self._last_walk_extra
            )

        if extra is not None:
            extra.update(self._last_walk_extra)
        if self._last_walk_result:
            return self._last_walk_result + self.page_offset(vaddr)
        return None



class _PmapX86(Pmap):
    """
    Specialization of Pmap for Intel
    """

    def __init__(self, pmap: lldbwrap.SBValue, name: Optional[str]=None):
        super().__init__(pmap, name)

        target = pmap.GetTarget()
        self.physmap_base = target.FindFirstGlobalVariable('physmap_base').xGetValueAsInteger()

    @property
    def page_size(self):
        return 4096

    def kvtophys(self, vaddr: int) -> int:
        return vaddr - self.phsmap_base

    def walk(self, vaddr: int, extra: Optional[dict] = None) -> Optional[int]:
        return PmapWalkX86_64(value(self.sbv), vaddr, 0)


class VMMap(object):
    """ Helper class to manipulate a vm_map_t"""

    def __init__(self, vm_map, name=None):
        self.sbv  = vm_map
        self.name = name
        self.rb   = RB_HEAD(
            vm_map.chkGetValueForExpressionPath(".hdr.rb_head_store"),
            "entry",
            self.entry_compare
        )

        vme_type = gettype('struct vm_map_entry')
        self.to_entry = vme_type.xContainerOfTransform('store')

    def entry_compare(self, rb_entry, address):
        vme = self.to_entry(rb_entry)

        if vme.xGetScalarByPath(".links.end") <= address:
            return 1
        if address < vme.xGetScalarByPath(".links.start"):
            return -1
        return 0

    def find(self, address):
        ent = self.rb.find(address)
        return self.to_entry(ent) if ent else None

    def describe(self, verbose=False):
        fmt = (
            "VM Map Info\n"
            " vm map               : {&v:#x} \n"
        )
        if self.name:
            fmt += (
                " vm map name          : {m.name:s} \n"
            )
        fmt += (
            " pmap                 : {$v.pmap:#x} \n"
            " vm size              : {$v.size|human_size} ({$v.size:,d} bytes) \n"
            " entries              : {$v.hdr.nentries} \n"
            " map range            : "
                "{$v.hdr.links.start:#x} - {$v.hdr.links.end:#x}\n"
            " map pgshift          : {$v.hdr.page_shift}\n"
        )
        print(xnu_format(fmt, m=self, v=self.sbv))


class VMMapEntry(MemoryObject):
    """ Memory Object for a kernel map memory entry """

    MO_KIND = "kernel map entry"

    def __init__(self, kmem, address, vm_map):
        super().__init__(kmem, address)
        self.vm_map = vm_map
        self.sbv    = vm_map.find(address)

    @property
    def object_range(self):
        sbv = self.sbv
        if sbv:
            return MemoryRange(
                sbv.xGetScalarByPath('.links.start'),
                sbv.xGetScalarByPath('.links.end')
            )

        base = self.address & ~self.kmem.page_mask
        return MemoryRange(base, base + self.kmem.page_size)

    @property
    def vme_offset(self):
        return self.sbv.xGetScalarByName('vme_offset') << 12

    @property
    def vme_object_type(self):
        sbv = self.sbv
        if sbv.xGetScalarByName('is_sub_map'):
            return "submap"
        if sbv.xGetScalarByName('vme_kernel_object'):
            return "kobject"
        return "vm object"

    @property
    def vme_object(self):
        kmem = self.kmem
        sbv  = self.sbv

        if sbv.xGetScalarByName('is_sub_map'):
            addr = sbv.xGetScalarByName('vme_submap') << 2
            return (addr, kmem.vm_map_type)

        if sbv.xGetScalarByName('vme_kernel_object'):
            return (kmem.vm_kobject.GetLoadAddress(), kmem.vmo_type)

        packed = sbv.xGetScalarByName('vme_object_or_delta')
        addr   = kmem.vm_page_packing.unpack(packed)
        return (addr, kmem.vmo_type)

    @property
    def pages(self):
        return self.object_range.size >> self.kmem.page_shift

    def describe(self, verbose=False):

        self.vm_map.describe()

        if not self.sbv:
            fmt = (
                "Kernel Map Entry Info\n"
                " No memory mapped at this address\n"
            )
            print(xnu_format(fmt))
            return

        fmt = (
            "VM Map Entry Info\n"
            " vm entry             : {&v:#x}\n"
            " start / end          : "
                "{$v.links.start:#x} - {$v.links.end:#x} "
                "({0.pages:,d} pages)\n"
            " vm tag               : {$v.vme_alias|vm_kern_tag}\n"
        )
        range_id = next((
            i
            for i, r in enumerate(self.kmem.kmem_ranges)
            if r.contains(self.address)
        ), None)
        if range_id:
            fmt += (
                " vm range id          : {range_id}\n"
            )
        fmt += (
            " protection           : "
                "{$v.protection|vm_prot}/{$v.max_protection|vm_prot}\n"
            " vm object            : "
                "{0.vme_object_type} ({0.vme_object[0]:#x})\n"
            " entry offset         : {0.vme_offset:#x}\n"
        )
        print(xnu_format(fmt, self, v=self.sbv, range_id=range_id))


@whatis_provider
class KernelMapWhatisProvider(WhatisProvider):
    """
    Whatis Provider for the kernel map ranges
    """

    def claims(self, address):
        kmem = self.kmem

        return (
                any(r.contains(address) for r in kmem.kmem_ranges)
                or kmem.iokit_range.contains(address)
        )

    def lookup(self, address):
        kmem = self.kmem

        if any(r.contains(address) for r in kmem.kmem_ranges):
            return VMMapEntry(kmem, address, VMMap(kmem.kernel_map, 'kernel_map'))

        iokit_pageable_map_data = kmem.target.chkFindFirstGlobalVariable('gIOKitPageableMap')
        iokit_pageable_vm_map = iokit_pageable_map_data.chkGetChildMemberWithName("map").Dereference()
        return VMMapEntry(kmem, address, VMMap(iokit_pageable_vm_map, "gIOKitPageableMap.map"))


__all__ = [
    Pmap.__name__,
    VMMap.__name__,
    VMMapEntry.__name__,
    KernelMapWhatisProvider.__name__,
]
