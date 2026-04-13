from abc import (
    ABCMeta,
    abstractmethod,
    abstractproperty,
)
import argparse
import itertools
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
from core.caching import (
    LazyTarget,
)

from .kmem   import MemoryRange, KMem
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

    def tag_storage(self, vaddr: int) -> (Optional[int], Optional[int], Optional[int]):
        """
        Finds the tag storage parameters for the specified virtual address

        @param vaddr (int)
            the virtual address to resolve

        @returns (tag_vaddr, tag_paddr, nibble_shift)
            - tag_vaddr is the virtual address in the PAPT of the ATag storage
            - tag_paddr is the physical address of the ATag storage
            - nibble shift is 0xf0 or 0x0f to denote which nibble holds the tag

            (None, None, None) is returned if the virtual address isn't tagged
            or the memory isn't resident for this map.
        """

        return (None, None, None)

    def get_tag(self, vaddr: int) -> Optional[int]:
        """
        Returns the tag for this virtual address or None
        """

        return None

    def ldg(self, vaddr: int) -> int:
        """
        Fixes up a virtual address with the proper tag, emulating the arm LDG
        instruction
        """

        tag = self.get_tag(vaddr)
        if tag is None:
            return vaddr
        return (vaddr & 0xf0ffffffffffffff) | (tag << 56)

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

        if target.FindFirstGlobalVariable('gARM_FEAT_MTE').IsValid():
            self.has_mte = target.FindFirstGlobalVariable('gARM_FEAT_MTE').xGetValueAsInteger()
        else:
            self.has_mte = False

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

    @property
    @caching.cache_statically
    def tag_coverage_start_phys(self, target=None):
        """
        The physical address of the start of the tag covered region
        """
        return target.FindFirstGlobalVariable('gDramBase').xGetValueAsInteger()

    @property
    @caching.cache_statically
    def tag_storage_start_phys(self, target=None):
        """
        The physical address of the start of the tag storage region
        """
        return target.FindFirstGlobalVariable('mte_tag_storage_start').xGetValueAsInteger()

    @property
    @caching.cache_statically
    def tag_storage_end_phys(self, target=None):
        """
        The physical address of the end of the tag storage region
        """
        return target.FindFirstGlobalVariable('mte_tag_storage_end').xGetValueAsInteger()

    def is_tagged(self, vaddr: int) -> bool:
        """
        Returns whether the passed in virtual address is tagged
        """
        if not self.has_mte:
            return False

        extra = {}
        paddr = self.walk(vaddr, extra)
        if paddr is None:
            return False

        return (extra['tte'][-1].value >> 2) & 0x7 == 4

    def tag_storage(self, vaddr: int) -> (Optional[int], Optional[int], Optional[int]):
        if not self.has_mte:
            return (None, None, None)

        extra = {}
        paddr = self.walk(vaddr, extra)
        if paddr is None:
            return (None, None, None)

        tte = extra['tte'][-1]
        if (tte.value >> 2) & 0x7 != 4:
            return (None, None, None)

        offset       = paddr - self.tag_coverage_start_phys
        tag_paddr    = self.tag_storage_start_phys + offset // 32
        nibble_shift = (offset & 0x10) >> 2
        return (self.phystokv(tag_paddr), tag_paddr, nibble_shift)

    def get_tag(self, vaddr: int) -> Optional[int]:
        addr, _, shift = self.tag_storage(vaddr)
        if addr is not None:
            return (self.sbv.GetTarget().xReadUInt8(addr) >> shift) & 0xf
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
        kmem = KMem.get_shared()

        self.sbv        = vm_map
        self.name       = name
        self.root       = vm_map.chkGetChildMemberWithName("root")
        self.shift      = vm_map.xGetScalarByPath('.hdr.page_shift')

        self.vmn_type   = gettype('struct vm_map_store_node')
        self.vmn_unpack = kmem.vmn_packing.unpack
        self.vmn_make   = kmem.vmn_packing.make_value

        self.vmc_type   = gettype('struct vm_guard_object_chunk')
        self.vme_type   = gettype('struct vm_map_entry')
        self.vme_unpack = kmem.vme_packing.unpack
        self.vme_make   = kmem.vme_packing.make_value

    def entry_compare(self, rb_entry, address):
        vme = self.to_entry(rb_entry)

        if vme.xGetScalarByPath(".links.end") <= address:
            return 1
        if address < vme.xGetScalarByPath(".links.start"):
            return -1
        return 0

    def find(self, addr):
        node = self.vmn_make(
            self.root.xGetScalarByPath('.vmsr_root.vmsp_packed'),
            self.vmn_type
        )

        while True:
            for i in range(0, node.xGetScalarByName('vmsn_count')):
                key = node.xGetScalarByPath(f'.vmsn_keys[{i}]')
                if addr < key:  i -= 1
                if addr <= key: break

            if node.xGetScalarByName('vmsn_leaf'):
                ptr   = node.xGetScalarByPath(f'.vmsl_ptrs[{i}].vmsp_packed')
                chunk = node.xGetScalarByPath(f'.vmsl_ptrs[{i}].vmsp_chunk')

                if not ptr:
                    return None

                if not chunk:
                    return self.vme_make(ptr, self.vme_type)

                chunk = self.vme_make(ptr, self.vmc_type)
                ptr   = chunk.xGetScalarByPath(f'.vgoc_ptrs[0].vmsp_packed')
                vme   = self.vme_make(ptr, self.vme_type) if ptr else None

                while vme and vme.xGetScalarByPath('.links.end') <= addr:
                    vme = vme.chkGetValueForExpressionPath('.links.next[0]')

                if vme and vme.xGetScalarByPath('.links.start') <= addr:
                    return vme
                return None

            ptr  = node.xGetScalarByPath(f'.vmsn_ptrs[{i}].vmsp_packed')
            node = self.vmn_make(ptr, self.vmn_type)

    def _dump_chunk_slot(self, chunk, end, sep):
        start       = chunk.xGetScalarByName('vgoc_start') << 16
        if start & (1 << 47): start |= 0xffff000000000000

        count       = chunk.xGetScalarByName('vgoc_count')
        size_shift  = chunk.xGetScalarByName('vgoc_granule')
        granule     = 1 << size_shift
        bitmap      = chunk.xGetScalarByName('vgoc_bitmap')
        slab        = chunk.xGetScalarByName('vgoc_slab')
        used        = count - bin(bitmap).count('1')
        qtn         = chunk.xGetScalarByName('vgoc_quarantined')
        avail       = chunk.xGetScalarByName('vgoc_available')
        guards      = max(count // 4, 1)

        print(f"  {sep} │")
        print(f"  {sep} │ slab:     {slab:#018x}")
        print(f"  {sep} │ config:   {count} x "
              f"{1 << (size_shift % 10)}{'BKMGT'[size_shift // 10]}, "
              f"{guards} guards")
        print(f"  {sep} │ avail:    {avail}")
        print(f"  {sep} │ used:     {used}")
        print(f"  {sep} │ qtn:      {qtn}")
        print(f"  {sep} │")

        ptr = chunk.xGetScalarByPath(f'.vgoc_ptrs[0].vmsp_packed')
        vme = self.vme_make(ptr, self.vme_type) if ptr else None

        for idx in range(count):
            cur  = start + idx * granule
            end  = cur + granule
            sep2 = None
            lbl  = f"{sep} │{' ' if (bitmap >> idx) & 1 else '•'}{idx:>2}"

            if idx + 1 == count:
                lbl = f"{sep} ╰{' ' if (bitmap >> idx) & 1 else '•'}{idx:>2}"

            while cur < end:
                if vme:
                    vme_start = vme.xGetScalarByPath('.links.start')
                    vme_end   = vme.xGetScalarByPath('.links.end')
                    if cur < vme_start:
                        lim = min(end, vme_start)
                    else:
                        lim = min(end, vme_end)
                else:
                    vme_start = vme_end = lim = end
                pgs = (lim - cur) >> self.shift

                if sep2 and lim == end:
                    sep2 = "╰"

                if sep2 and idx + 1 == count:
                    lbl = f"{lbl[:2]}   {sep2}"
                elif sep2:
                    lbl = f"{lbl[:3]}  {sep2}"

                if not vme or cur < vme_start:
                    print(f"  {lbl} ------------------ "
                          f"{cur:#018x}:{lim:#018x} {pgs:9,d}")
                else:
                    print(f"  {lbl} {vme.GetLoadAddress():#018x} "
                          f"{cur:#018x}:{lim:#018x} {pgs:9,d}")

                cur = lim
                if vme and cur >= vme_end:
                    vme = vme.chkGetValueForExpressionPath('.links.next[0]')

                sep2 = "│"

    def dump(self, as_dict=False):
        """
        Dump the VM map structure either as formatted output or as a dictionary.

        Args:
            as_dict (bool): If True, return a dictionary. If False, print formatted output.

        Returns:
            dict or None: Dictionary if as_dict=True, None if as_dict=False
        """

        data = self.dump_as_dict()
        if as_dict:
            return data

        # Format and print the structured data
        for row in data.get("rows", []):
            depth = row["depth"]
            print(f"row {depth}")

            for node in row.get("nodes", []):
                idx = node["index"]
                address = node["address"]
                start = node["start"]
                end = node["end"]

                print(f"  {depth}.{idx:<3}─ "
                      f"{address:#018x} "
                      f"{start:#018x}:{end:#018x}")

                for entry in node.get("entries", []):
                    i = entry["entry_index"]
                    nstart = entry["start"]
                    nend = entry["end"]

                    # Determine separator
                    if i + 1 == node["count"]:
                        sep = "╰"
                    else:
                        sep = "│"

                    if "error" in entry:
                        print(f"  {sep} {i:<2}   Error: {entry['error']}")
                        continue

                    if entry["type"] == "node":
                        n = entry["pointer"]
                        h = entry["holes"]

                        print(f"  {sep} {i:<2}   "
                              f"{n:#018x} {nstart:#018x}:{nend:#018x} {h:#010x}")

                    else:  # leaf
                        v   = entry["vme_address"]
                        pgs = entry["pages"]

                        if v is not None:
                            print(f"  {sep} {i:<2}   "
                                  f"{v:#018x} {nstart:#018x}:{nend:#018x} "
                                  f"{pgs:9,d}")
                        else:
                            print(f"  {sep} {i:<2}   "
                                  f"------------------ {nstart:#018x}:{nend:#018x} "
                                  f"{pgs:9,d}")

                    # Update separator for next iteration
                    if i + 1 == node["count"]:
                        sep = ' '

                    if entry["type"] == "leaf" and entry["is_chunk"]:
                        c = self.vme_make(entry["packed"], self.vmc_type)
                        self._dump_chunk_slot(c, nend, sep)


    def dump_as_dict(self):
        """Return the VM map structure as a dictionary instead of printing it"""
        # Check if root is properly initialized
        root_packed = self.root.xGetScalarByPath('.vmsr_root.vmsp_packed')
        node = self.vmn_make(root_packed, self.vmn_type)

        result = {"rows": []}

        for depth in itertools.count():

            leaf = node.xGetScalarByName('vmsn_leaf')
            if not leaf:
                child = self.vmn_make(node.xGetScalarByPath('.vmsn_ptrs[0].vmsp_packed'), self.vmn_type)

            row_data = {
                "depth": depth,
                "nodes": []
            }

            for idx in itertools.count():
                spacked = node.xGetScalarByPath('.vmsn_next_sibling.vmsp_packed')
                sibling = self.vmn_make(spacked, gettype('struct vm_map_store_node')) if spacked else 0
                start   = node.xGetScalarByPath('.vmsn_keys[0]')
                end     = sibling.xGetScalarByPath('.vmsn_keys[0]') if spacked else 0xffffffffffffffff
                count   = node.xGetScalarByName('vmsn_count')

                node_data = {
                    "index": idx,
                    "address": int(node.GetLoadAddress()),
                    "start": int(start),
                    "end": int(end),
                    "count": int(count),
                    "entries": []
                }

                for i in range(0, count):
                    nstart = node.xGetScalarByPath(f'.vmsn_keys[{i}]')
                    if i + 1 < count:
                        nend = node.xGetScalarByPath(f'.vmsn_keys[{i + 1}]')
                    else:
                        nend = end

                    entry_data = {
                        "entry_index": i,
                        "start": int(nstart),
                        "end": int(nend)
                    }

                    if not leaf:
                        n = node.xGetScalarByPath(f'.vmsn_ptrs[{i}].vmsp_packed')
                        n = self.vmn_unpack(n)
                        h = node.xGetScalarByPath(f'.vmsn_holes[{i}]')

                        entry_data.update({
                            "type": "node",
                            "pointer": int(n),
                            "holes": int(h),
                        })
                    else:
                        p = node.xGetScalarByPath(f'.vmsl_ptrs[{i}].vmsp_packed')
                        c = node.xGetScalarByPath(f'.vmsl_ptrs[{i}].vmsp_chunk')
                        v = self.vme_unpack(p) if p else 0
                        pgs = (nend - nstart) >> self.shift

                        entry_data.update({
                            "type": "leaf",
                            "vme_address": int(v) if p and v else None,
                            "packed": int(p) if p else None,
                            "is_chunk": int(c),
                            "pages": int(pgs),
                        })
                    node_data["entries"].append(entry_data)

                row_data["nodes"].append(node_data)
                if not spacked: break
                node = sibling

            result["rows"].append(row_data)
            if leaf: break
            node = child

        return result

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
        go = self.sbv.xGetScalarByPath('.links.chunk.vmsp_packed')
        if go:
            fmt += (
                f" go chunk             : {self.kmem.vme_packing.unpack(go):#x}\n"
            )
        range_id = next((
            i + 1
            for i, r in enumerate(self.kmem.kmem_ranges)
            if r.contains(self.address)
        ), None)
        if range_id:
            fmt += (
                " vm range id          : {range_id|vm_kern_range_id}\n"
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


@SBValueFormatter.converter("mte_cell_state")
def mte_cell_state_converter(state):
    return GetEnumName('cell_state_t', state, 'MTE_STATE_')

class _MTEArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgumentError(message)

class _MTEHelpFormatter(argparse.HelpFormatter):
    """
    Class used to pretty print help for XNU commands
    """

    def __init__(self, prog, **kwargs):
        kwargs['width'] = 80
        super(_MTEHelpFormatter, self).__init__(prog, **kwargs)

        self._ws_re = re.compile(r'\s+', re.ASCII)
        self._p_re  = re.compile(r'\n\n+')

    def _reflow(self, text, width, indent):
        import textwrap

        return textwrap.fill(
            self._ws_re.sub(' ', text).strip(),
            width=80,
            initial_indent=indent,
            subsequent_indent=indent,
        )

    def _fill_text(self, text, width, indent):
        return "\n\n".join(
            self._reflow(s, width, indent if i == 0 else indent + "  ")
            for i, s in enumerate(self._p_re.split(text))
        )

class MTECommand(object, metaclass=ABCMeta):
    """
    Inspect and debug MTE related problems
    """

    COMMAND     = "mte"
    _sub_cmds   = [ 'atag', 'atag-read', 'info', 'ldg' ]

    #
    # Initialization
    #

    def __init__(self):
        cls = self.__class__

        self.target         = None
        self.cmd_name       = cls.COMMAND
        self.verbosity      = 0
        self.O              = None

        self._profile       = None
        self._coverage      = None

        opt_parser = _MTEArgumentParser(
            prog=cls.COMMAND,
            description=cls.__doc__,
            formatter_class=_MTEHelpFormatter,
            exit_on_error=False,
        )

        cls.make_opts(opt_parser)

        sub_parser = opt_parser.add_subparsers(
            title='valid subcommands',
            dest='subcommand',
            required=True,
        )

        for sub_cmd_name in cls._sub_cmds:
            fn_name = sub_cmd_name.replace("-", "_")
            fn      = getattr(cls, "cmd_" + fn_name)
            help    = fn.__doc__.strip().split("\n", 1)[0].strip()

            parser = sub_parser.add_parser(
                sub_cmd_name,
                help=help,
                description=fn.__doc__,
                formatter_class=_MTEHelpFormatter,
                exit_on_error=False,
            )

            gen_parser = getattr(cls, "make_opts_" + fn_name, None)
            if gen_parser: gen_parser(parser)

        self.opt_parser = opt_parser

    #
    # Help handling
    #

    def _print_help(self):
        self.opt_parser.print_help()
        print("")

    def get_short_help(self):
        """ Return a short help for the command (from your class short_help) """

        return self.__class__.__doc__.strip().split("\n", 1)[0]

    def get_long_help(self):
        """ Return a long help for the command (generated from the option parser) """

        return "\n" + self.opt_parser.format_help()


    #
    # Execution
    #

    def __call__(self, cmd_args, O=None):
        self.target = caching.LazyTarget.GetTarget()
        self.O      = O

        try:
            args, argv = self.opt_parser.parse_known_args(cmd_args)

            if argv:
                raise ArgumentError(
                    f"unrecognized arguments: {' '.join(argv)}"
                )
        except Exception as err:
            self._print_help()
            O.resultObj.SetError(str(err))
            return

        getattr(self, f"cmd_{args.subcommand.replace('-', '_')}")(args)


    #
    # Helpers to extend option parsing
    #

    @staticmethod
    def Int(arg: str) -> int:
        """
        ArgumentParser type converter returning an Int out of lldb expressions
        """

        return caching.LazyTarget.GetTarget().chkEvaluateExpression(arg).xGetValueAsInteger()

    Address = Int

    @staticmethod
    def Value(type: str, structor: Optional = None):
        """
        ArgumentParser type converter returning an SBValue of the specified type
        """

        def convert(arg: str):
            target = caching.LazyTarget.GetTarget()
            arg    = target.chkEvaluateExpression(arg).xGetValueAsInteger()
            value  = target.xCreateValueFromAddress(None, arg, gettype(type))
            return value if structor is None else structor(value)

        return convert


    #
    # Actual command implementation
    #

    @property
    def mte_cells(self):
        return self.target.FindFirstGlobalVariable('mte_info_cells').Dereference()

    @property
    def mte_lists(self):
        return self.target.FindFirstGlobalVariable('mte_info_lists')

    @property
    def mte_free_queues(self):
        return self.target.FindFirstGlobalVariable('mte_free_queues')

    @classmethod
    def make_opts(cls, parser):
        parser.add_argument(
            "-P", "--pmap",
            type=cls.Value("struct pmap", Pmap),
            metavar='pmap',
            default="kernel_pmap",
            help="The pmap to use to resolve virtual addresses (default: kernel_pmap)",
        )


    #
    # mte atag
    #

    @classmethod
    def make_opts_atag(cls, parser):
        parser.add_argument(
            "address",
            type=cls.Address,
            help="The virtual address to print atag information for"
        )

    def cmd_atag(self, args):
        """
        Print the MTE tag storage info for a covered virtual address

        Print detailed information about the tag storage "cell"
        corresponding to a given virtual address
        """

        pmap  = args.pmap
        vaddr = args.address

        tag_vaddr, tag_paddr, shift = pmap.tag_storage(vaddr)

        if tag_vaddr is None:
            print(f"{vaddr:#x} isn't tagged")
            return

        index  = (tag_paddr - pmap.tag_storage_start_phys) >> 14
        slot   = (tag_paddr >> 9) & 0x1f
        cell   = self.mte_cells.xGetSiblingValueAtIndex(index)

        cpaddr = pmap.tag_coverage_start_phys + index * (32 << 14)
        cvaddr = pmap.phystokv(cpaddr)

        slots = "".join('x' if pmap.is_tagged(cvaddr + (x << 14)) else '.'
            for x in range(0, 32))

        print(xnu_format(
            u"Tag information\n"
            u" pmap                 : {&pmap:#x}\n"
            f" virtual address      : {vaddr:#x}\n"
            f" tag storage address  : {tag_paddr:#x}\n"
            f" covered page index   : {slot:d}\n"
            f" tag storage nibble   : {0xf0 >> shift:#04x}\n"
            f" tag value            : {pmap.get_tag(vaddr):#x}\n"
            u"\n"
            u"MTE Cell Info\n"
            u" cell                 : {&c:#x}\n"
            f" index                : {index}\n"
            u" state                : {$c.state|mte_cell_state}\n"
            u" free pages           : {$c.free_page_count}\n"
            u" mte slots used       : {$c.mte_page_count}\n"
            u"                                  1         2         3\n"
            u"                        0....5....0....5....0....5....0.\n"
            f" mte enabled slots    : {slots:s}\n"
            f"                        {'':{slot}s}^\n",
            pmap=pmap.sbv, index=index, c=cell,
        ))

    #
    # mte atag-read
    #

    @classmethod
    def make_opts_atag_read(cls, parser):
        parser.add_argument(
            "begin",
            type=cls.Address,
            help="The first virtual address to print tag storage for",
        )
        parser.add_argument(
            "end",
            nargs="?",
            type=cls.Address,
            help="The last virtual address to printing tag storage for",
        )

    def cmd_atag_read(self, args):
        """
        Dump tags for a range of memory

        Dumps the atag space corresponding to the range of addresses
        from <begin> to <end>.  If unspecified, <end> is taken as 512
        bytes after <begin> in order to dump 32 tags.
        """

        pmap       = args.pmap
        start_addr = args.begin
        end_addr   = args.end

        stride = 16 * 32
        start  = start_addr & -stride
        marks  = {}

        if end_addr is None:
            end = (start_addr + 2 * stride + stride - 1) & -stride
        else:
            end = (end_addr + stride - 1) & -stride

        tag_vaddr, _, _ = pmap.tag_storage(start_addr)
        if tag_vaddr is not None:
            marks[tag_vaddr] = '>'

        def print_extra(start):
            return " {:#x}".format(addr)

        print("{:18s}  {:68s}  {:18s}".format(
            "atag address", "tag values", "virtual address"))
        print("=" * 108)

        for addr in range(start, end, stride):
            tag_vaddr, _, _ = pmap.tag_storage(addr)

            if addr != start and pmap.page_offset(addr) == 0:
                print("-" * 108)

            if tag_vaddr is None:
                print("{:87s}  {}".format(
                    "no tag information", print_extra(tag_vaddr)))
                continue

            try:
                data = self.target.xReadBytes(tag_vaddr, 16)
                print_hex_data(data, tag_vaddr, prefix="", marks=marks, extra=print_extra)
            except:
                print("{:87s}  {}".format(
                    "** unable to read tag memory **", print_extra(tag_vaddr)))

    #
    # mte info
    #

    def _make_mask(self, mask, bits):
        return "".join('x' if mask & (1 << i) else '.' for i in range(0, bits))

    def _describe_list(self, name, index, has_buckets = False):
        l = self.mte_lists.chkGetChildAtIndex(index)

        if has_buckets:
            fmt    = " {0:20s} : {$l.count:9,d}  [ {counts:s} ]"
            counts = " ".join(
                "{:9,d}".format(l.xGetScalarByPath('.buckets[{}].head.cell_count'.format(i)))
                for i in range(0,5)
            )

        else:
            fmt    = " {0:20s} : {$l.count:9,d}"
            counts = ""

        print(xnu_format(fmt, name, counts=counts, l=l))
        return l.xGetIntegerByName('count')

    def _describe_free_queue(self, name, index):
        fmt    = " {0:20s} : {$q.vmpfq_count:9,d}"
        q      = self.mte_free_queues.chkGetChildAtIndex(index)
        print(xnu_format(fmt, name, q=q))
        return q.xGetIntegerByName('vmpfq_count')


    def cmd_info(self, args):
        """
        Dumps the state of the MTE info data structure
        """

        free     = self.target.FindFirstGlobalVariable('vm_page_free_count').xGetValueAsInteger()
        tagged   = self.target.FindFirstGlobalVariable('vm_page_tagged_count').xGetValueAsInteger()
        taggable = self.target.FindFirstGlobalVariable('vm_page_free_taggable_count').xGetValueAsInteger()
        ts_wired = self.target.FindFirstGlobalVariable('vm_page_wired_tag_storage_count').xGetValueAsInteger()

        fmt = (
            "MTE Info Stats\n"
            " cells address        : {&cells:#x}\n"
            " lists address        : {&lists:#x}\n"
            "\n"
            "Lists                       count  [         0       1-8      9-16     17-24     25-32 ]")

        print(xnu_format(fmt, lists=self.mte_lists, cells=self.mte_cells))

        self._describe_list("disabled", 0)
        self._describe_list("pinned", 1)
        self._describe_list("deactivating", 2)
        self._describe_list("claimed", 3, True)
        self._describe_list("inactive", 4, True)
        self._describe_list("reclaiming", 5)
        self._describe_list("activating", 6)
        active0 = self._describe_list("active 0", 7, True)
        active  = self._describe_list("active 1+", 8)
        if active == 0:
            frag = 0
        else:
            frag = 100 - tagged * 100 / (32 * active)

        fmt = (
            "\n"
            "Free Queues"
        )
        print(xnu_format(fmt))
        self._describe_free_queue("untaggable 0", 0)
        self._describe_free_queue("untaggable 1", 1)
        self._describe_free_queue("untaggable 2", 2)
        self._describe_free_queue("active 0", 3)
        self._describe_free_queue("active 1", 4)
        self._describe_free_queue("active 2", 5)
        self._describe_free_queue("active 3", 6)
        self._describe_free_queue("activating", 7)

        print(
            "\n"
            "Statistics\n"
            f" taggable free pages  : {taggable:9,d}\n"
            f" free pages           : {free:9,d}\n"
            f" tagged pages         : {tagged:9,d}\n"
            f" tag storage active   : {active + active0:9,d}\n"
            f" tag storage wired    : {ts_wired:9,d}\n"
            f" fragmentation        : {frag:9.1f}%\n"
        )

    #
    # mte ldg
    #

    @classmethod
    def make_opts_ldg(cls, parser):
        parser.add_argument(
            "address",
            nargs='+',
            type=cls.Address,
            help="An address to fix with the proper tag",
        )

    def cmd_ldg(self, args):
        """
        Fix a pointer with its proper tag
        """

        for address in args.address:
            print(f"{args.pmap.ldg(address):#x}")


@lldb_command("mte", 'P:', fancy=True)
def mte_dispatch(cmd_args=None, cmd_options={}, O=None):
    """
    Inspect and debug MTE related problems

    usage: mte [-P pmap] {atag,atag-read,info,ldg} ...

    optional arguments:
      -P pmap               The pmap to use to resolve virtual addresses
                            (default: kernel_pmap)

    valid subcommands:
        atag                Print the MTE tag storage info for a covered virtual
                            address
        atag-read           Dump tags for a range of memory
        info                Dumps the state of the MTE info data structure
        ldg                 Fix a pointer with its proper tag
    """

    if "-P" in cmd_options:
        cmd_args = ["-P", cmd_options["-P"]] + cmd_args
    MTECommand()(cmd_args, O=O)


__all__ = [
    Pmap.__name__,
    VMMap.__name__,
    VMMapEntry.__name__,
    KernelMapWhatisProvider.__name__,
]
