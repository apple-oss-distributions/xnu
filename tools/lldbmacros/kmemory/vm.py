from __future__ import absolute_import, division, print_function

from builtins import range
from builtins import object

import six
import struct

from core import (
    gettype,
    xnu_format,
    SBValueFormatter,
)
from core.collections import (
    RB_HEAD,
)

from .kmem   import MemoryRange
from .btlog  import BTLog, BTLibrary
from .whatis import *


@SBValueFormatter.converter("vm_prot")
def vm_prot_converter(prot):
    PROT_STR = "-rw?x"
    return PROT_STR[prot & 1] + PROT_STR[prot & 2] + PROT_STR[prot & 4]


class VMMap(object):
    """ Helper class to manipulate a vm_map_t """

    def __init__(self, vm_map):
        self.sbv = vm_map
        self.rb  = RB_HEAD(
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
            " pmap                 : {$v.pmap:#x} \n"
            " vm size              : {$v.size|human_size} ({$v.size:,d} bytes) \n"
            " entries              : {$v.hdr.nentries} \n"
            " map range            : "
                "{$v.hdr.links.start:#x} - {$v.hdr.links.end:#x}\n"
            " map pgshift          : {$v.hdr.page_shift}\n"
        )
        print(xnu_format(fmt, self, v=self.sbv))


class VMMapEntry(MemoryObject):
    """ Memory Object for a kernel map memory entry """

    MO_KIND = "kernel map entry"

    def __init__(self, kmem, address, vm_map):
        super(VMMapEntry, self).__init__(kmem, address)
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
            " vm range id          : {range_id}\n"
            " protection           : "
                "{$v.protection|vm_prot}/{$v.max_protection|vm_prot}\n"
            " vm object            : "
                "{0.vme_object_type} ({0.vme_object[0]:#x})\n"
            " entry offset         : {0.vme_offset:#x}\n"
        )
        print(xnu_format(fmt, self, v=self.sbv,
            range_id=next(
                i
                for i, r in enumerate(self.kmem.kmem_ranges)
                if r.contains(self.address)
            )
        ))


@whatis_provider
class KernelMapWhatisProvider(WhatisProvider):
    """
    Whatis Provider for the kernel map ranges
    """

    def claims(self, address):
        return any(r.contains(address) for r in self.kmem.kmem_ranges)

    def lookup(self, address):
        return VMMapEntry(self.kmem, address, VMMap(self.kmem.kernel_map))


__all__ = [
    VMMap.__name__,
    VMMapEntry.__name__,
    KernelMapWhatisProvider.__name__,
]
