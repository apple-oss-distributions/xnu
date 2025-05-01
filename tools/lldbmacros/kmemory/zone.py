import struct

from core import (
    caching,
    gettype,
    lldbwrap,
    xnu_format,
)
from .kmem   import KMem, MemoryRange
from .vm     import Pmap
from .btlog  import BTLog, BTLibrary
from .whatis import *

# FIXME: should not import this from xnu / utils
from xnu import (
    GetSourceInformationForAddress,
    print_hex_data,
)

class ZoneBitsMemoryObject(MemoryObject):
    """ Memory Object for pointers in the Zone Bitmaps range """

    MO_KIND = "zone bitmap"

    @property
    def object_range(self):
        return self.kmem.bits_range

    def describe(self, verbose=False):
        #
        # Printing something more useful would require crawling
        # all zone chunks with non inline bitmaps until we find
        # the one.
        #
        # This is very expensive and really unlikely to ever
        # be needed for debugging.
        #
        # Moreover, bitmap pointers do not leak outside
        # of the bowels of zalloc, dangling pointers to
        # this region is very unexpected.
        #
        print("Zone Bitmap Info")
        print(" N/A")
        print()


class ZonePageMetadata(MemoryObject):
    """ Memory Object for Zone Page Metadata """

    MO_KIND = "zone metadata"

    def __init__(self, kmem, address):
        super().__init__(kmem, address)

        if not kmem.meta_range.contains(address):
            raise IndexError("{:#x} is not inside the meta range {}".format(
                address, kmem.meta_range))

        #
        # Resolve the ZPM we fall into
        #
        size = kmem.zpm_type.GetByteSize()
        idx  = (address - kmem.meta_range.start) // size
        sbv  = kmem.target.xCreateValueFromAddress(None,
            kmem.meta_range.start + idx * size, kmem.zpm_type)
        chunk_len = sbv.xGetIntegerByName('zm_chunk_len')

        self.mo_sbv = sbv
        self.kmem   = kmem

        #
        # Compute the canonical ZPM
        #
        # 0xe = ZM_SECONDARY_PAGE
        # 0xf = ZM_SECONDARY_PCPU_PAGE
        #
        # TODO use a nice package to index enums by name,
        #      can't use GetEnumName() because it uses kern.*
        #
        if chunk_len in (0xe, 0xf):
            pg_idx    = sbv.xGetIntegerByName('zm_page_index')
            idx      -= pg_idx
            sbv       = sbv.xGetSiblingValueAtIndex(-pg_idx)
            chunk_len = sbv.xGetIntegerByName('zm_chunk_len')

        self.sbv        = sbv
        self._idx       = idx
        self._chunk_len = chunk_len

    @classmethod
    def _create_with_zone_address(cls, kmem, address):
        zone_range = kmem.zone_range
        if not zone_range.contains(address):
            raise IndexError("{:#x} is not inside the zone map {}".format(
                address, zone_range))

        index     = (address - zone_range.start) >> kmem.page_shift
        meta_addr = kmem.meta_range.start + index * kmem.zpm_type.GetByteSize()

        return ZonePageMetadata(kmem, meta_addr)

    @classmethod
    def _create_with_pva(cls, kmem, pva):
        address = ((pva | 0xffffffff00000000) << kmem.page_shift) & 0xffffffffffffffff
        return ZonePageMetadata._create_with_zone_address(kmem, address)

    @property
    def object_range(self):
        addr = self.sbv.GetLoadAddress()
        clen = self._chunk_len
        if clen == 1 and self.zone.percpu:
            clen  = self.kmem.ncpus
        size = self._chunk_len * self.kmem.zpm_type.GetByteSize()

        return MemoryRange(addr, addr + size)

    @property
    def zone(self):
        sbv = self.sbv
        return Zone(sbv.xGetIntegerByName('zm_index'))

    @property
    def pgz_slot(self):
        addr = self.page_addr
        kmem = self.kmem
        if kmem.pgz_range.contains(addr):
            return (addr - kmem.pgz_range.start) >> (kmem.page_shift + 1)
        return None

    def _pgz_alloc_frames(self, index):
        kmem   = self.kmem
        target = kmem.target
        bt     = kmem.pgz_bt.xGetSiblingValueAtIndex(index)
        return (
            kmem.stext + pc
            for pc in target.xIterAsInt32(
                bt.xGetLoadAddressByName('pgz_bt'),
                bt.xGetIntegerByName('pgz_depth')
            )
        )

    @property
    def pgz_alloc_bt_frames(self):
        return self._pgz_alloc_frames(2 * self.pgz_slot)

    @property
    def pgz_free_bt_frames(self):
        return self._pgz_alloc_frames(2 * self.pgz_slot + 1)

    def describe(self, verbose=False):
        kmem = self.kmem
        sbv  = self.sbv
        zone = self.zone

        chunk_len = self._chunk_len
        if zone.percpu:
            chunk_len = kmem.ncpus

        zone.describe()

        print("Zone Metadata Info")
        print(" chunk length         : {}".format(chunk_len))
        print(" metadata             : {:#x}".format(sbv.GetLoadAddress()))
        print(" page                 : {:#x}".format(self.page_addr))

        if sbv.xGetIntegerByName('zm_inline_bitmap'):
            if verbose:
                bitmap = [
                    "{:#010x}".format(sbv.xGetSiblingValueAtIndex(i).xGetIntegerByName('zm_bitmap'))
                    for i in range(self._chunk_len)
                ]
                print(" bitmap               : inline [ {} ]".format(" ".join(bitmap)))
            else:
                print(" bitmap               : inline")
        else:
            bref   = sbv.xGetIntegerByName('zm_bitmap')
            blen   = 1 << ((bref >> 29) & 0x7)
            bsize  = blen << 3
            baddr  = kmem.bits_range.start + 8 * (bref & 0x0fffffff)
            bitmap = (
                "{:#018x}".format(word)
                for word in kmem.target.xIterAsUInt64(baddr, blen)
            )

            if bref == 0:
                print(" bitmap               : None")
            elif not verbose:
                print(" bitmap               : {:#x} ({} bytes)".format(baddr, bsize))
            elif blen <= 2:
                print(" bitmap               : {:#x} ({} bytes) [ {} ]".format(
                    baddr, bsize, ' '.join(bitmap)))
            else:
                print(" bitmap               : {:#x} ({} bytes) [".format(baddr, bsize))
                for i in range(blen // 4):
                    print("  {}  {}  {}  {}".format(
                        next(bitmap), next(bitmap),
                        next(bitmap), next(bitmap)))
                print(" ]")

        print()

        mo_sbv = self.mo_sbv
        if sbv != mo_sbv:
            pg_idx = self.mo_sbv.xGetIntegerByName('zm_page_index')

            print("Secondary Metadata Info")
            print(" index                : {}/{}".format(pg_idx + 1, chunk_len))
            print(" metadata             : {:#x}".format(mo_sbv.GetLoadAddress()))
            print(" page                 : {:#x}".format(
                self.page_addr + (pg_idx << kmem.page_shift)))
            print()

        if verbose:
            print("-" * 80)
            print()
            print(str(self.mo_sbv))
            print()


    @property
    def next_pva(self):
        """ the next zone_pva_t queued after this Zone Page Metadata """

        return self.sbv.xGetIntegerByPath('.zm_page_next.packed_address')

    @property
    def page_addr(self):
        """ The page address corresponding to this Zone Page Metadata """

        kmem = self.kmem
        return kmem.zone_range.start + (self._idx << kmem.page_shift)

    def iter_all(self, zone):
        """ All element addresses covered by this chunk """

        base  = self.page_addr
        esize = zone.elem_outer_size
        offs  = zone.elem_inner_offs
        count = zone.chunk_elems
        run   = self.sbv.xGetIntegerByName('zm_chunk_len')

        return range(base + offs, base + (run << self.kmem.page_shift), esize)

    def is_allocated(self, zone, addr):
        """ Whether an address has the allocated bit set """

        if not self._chunk_len:
            return False

        sbv   = self.sbv
        base  = self.page_addr + zone.elem_inner_offs
        esize = zone.elem_inner_size
        idx   = (addr - base) // esize

        if sbv.xGetIntegerByName('zm_inline_bitmap'):
            w, b = divmod(idx, 32)
            mask = sbv.xGetSiblingValueAtIndex(w).xGetIntegerByName('zm_bitmap')
            return (mask & (1 << b)) == 0
        else:
            w, b  = divmod(idx, 64)
            bref  = sbv.xGetIntegerByName('zm_bitmap')
            kmem  = self.kmem
            baddr = kmem.bits_range.start + 8 * (bref & 0x0fffffff) + 8 * w
            return not (kmem.target.xReadUInt64(baddr) & (1 << b))

    def iter_allocated(self, zone):
        """ All allocated addresses in this this chunk """

        kmem  = self.kmem
        sbv   = self.sbv
        base  = self.page_addr

        # cache memory, can make enumeration twice as fast for smaller objects
        sbv.target.xReadBytes(base, self._chunk_len << kmem.page_shift)

        esize = zone.elem_outer_size
        base += zone.elem_inner_offs

        if sbv.xGetIntegerByName('zm_inline_bitmap'):
            for i in range(zone.chunk_elems):
                w, b = divmod(i, 32)
                if b == 0:
                    mask = sbv.xGetSiblingValueAtIndex(w).xGetIntegerByName('zm_bitmap')
                if not mask & (1 << b):
                    yield base + i * esize
        else:
            bref  = sbv.xGetIntegerByName('zm_bitmap')
            baddr = kmem.bits_range.start + 8 * (bref & 0x0fffffff)
            data  = kmem.target.xIterAsUInt64(baddr, 1 << ((bref >> 29) & 0x7))

            for i in range(zone.chunk_elems):
                b = i & 63
                if b == 0:
                    word = next(data)
                if not word & (1 << b):
                    yield base + i * esize


class ZoneHeapMemoryObject(MemoryObject):
    """ Memory Object for zone allocated objects """

    MO_KIND = "zone heap"

    def __init__(self, kmem, address):
        super().__init__(kmem, address)

        if not kmem.zone_range.contains(address):
            raise IndexError("{:#x} is not inside the zone range {}".format(
                address, kmem.zone_range))

        meta  = ZonePageMetadata._create_with_zone_address(kmem, address)
        zone  = meta.zone
        esize = zone.elem_outer_size

        if kmem.pgz_range.contains(address):
            real_addr = meta.sbv.xGetIntegerByName('zm_pgz_orig_addr')
            page_mask = kmem.page_mask
            elem_addr = (real_addr & page_mask) + (address & ~page_mask)
            elem_idx  = ((elem_addr & page_mask) - zone.elem_inner_offs) // esize
            self.real_addr = real_addr
            self.real_meta = ZonePageMetadata._create_with_zone_address(kmem, real_addr)
            self.pgz       = True
        else:
            base      = meta.page_addr + zone.elem_inner_offs
            elem_idx  = (address - base) // esize if address >= base else -1
            elem_addr = base + elem_idx * esize   if address >= base else None
            self.real_addr = elem_addr
            self.real_meta = meta
            self.pgz       = False

        self.kmem      = kmem
        self.meta      = meta
        self.zone      = zone
        self.elem_idx  = elem_idx
        self.elem_addr = elem_addr

    @property
    def object_range(self):
        if self.elem_idx >= 0:
            elem_addr = self.elem_addr
            elem_size = self.zone.elem_outer_size
            return MemoryRange(elem_addr, elem_addr + elem_size)

        base = self.meta.page_addr
        size = self.zone.elem_inner_offs
        return MemoryRange(base, base + size)

    @property
    def status(self):
        zone      = self.zone
        real_addr = self.real_addr

        if self.elem_idx < 0:
            return "invalid"

        elif not self.real_meta.is_allocated(zone, real_addr):
            return "free"

        elif real_addr in zone.cached():
            return "free (cached)"

        elif real_addr in zone.recirc():
            return "free (recirc)"

        else:
            return "allocated"

    def hexdump(self):
        print("Hexdump:")

        target = self.kmem.target
        zone   = self.zone
        eaddr  = self.elem_addr
        eend   = eaddr + zone.elem_inner_size
        delta  = self.real_addr - eaddr

        rz     = zone.elem_redzone
        start  = (eaddr & -16) - min(rz, 16) - 16
        end    = (eend + 16 + 15) & -16
        marks  = { self.address: '>' }
        phex   = print_hex_data


        if rz > 16:
            print(" " + "=" * 88)
            print(" {}".format("." * 18))

            try:
                data = target.xReadBytes(start + delta, eaddr - start)
                phex(data, start, "", marks)
            except:
                print(" *** unable to read redzone memory ***")
        else:
            try:
                data = target.xReadBytes(start + delta, eaddr - rz - start)
                phex(data, start, "", marks)
            except:
                pass

            print(" " + "=" * 88)

            if rz:
                try:
                    data = target.xReadBytes(eaddr - rz + delta, rz)
                    phex(data, eaddr - rz, "", marks)
                except:
                    print(" *** unable to read redzone memory ***")

        if rz:
            print(" {}".format("-" * 88))

        try:
            data = target.xReadBytes(eaddr + delta, eend - eaddr)
            phex(data, eaddr, "", marks)
        except:
            print(" *** unable to read element memory ***")

        print(" " + "=" * 88)

        try:
            data = target.xReadBytes(eend + delta, end - eend)
            phex(data, eend, "", marks)
        except:
            pass

        print()

    def describe(self, verbose=False):
        meta   = self.meta
        zone   = self.zone
        status = self.status
        btlog  = zone.btlog

        meta.describe()

        print("Zone Heap Object Info")

        print(" element index        : {}".format(self.elem_idx))
        print(" chunk offset         : {}".format(self.address - meta.page_addr))
        print(" status               : {}".format(status))
        if self.pgz:
            print(" pgz orig address     : {:#x}".format(self.real_addr))
            print()

            print("PGZ Allocation backtrace:")
            for pc in meta.pgz_alloc_bt_frames:
                print(" " + GetSourceInformationForAddress(pc))

            if status == 'free':
                print()

                print("PGZ Free backtrace:")
                for pc in meta.pgz_free_bt_frames:
                    print(" " + GetSourceInformationForAddress(pc))
        elif btlog and (btlog.is_log() or status == 'allocated'):
            record = next(btlog.iter_records(
                wantElement=self.elem_addr, reverse=True), None)
            if record:
                btlib = BTLibrary.get_shared()
                print(" last zlog backtrace",
                    *btlib.get_stack(record.ref).symbolicated_frames(prefix="  "), sep="\n")

        print()

        if self.elem_idx >= 0 and verbose:
            self.hexdump()


@whatis_provider
class ZoneWhatisProvider(WhatisProvider):
    """
    Whatis Provider for the zone ranges
    - metadata (bits and ZPM)
    - PGZ
    - regular heap objects
    """

    def __init__(self, kmem):
        super().__init__(kmem)

    def claims(self, address):
        kmem = self.kmem

        return any(
            r.contains(address)
            for r in (kmem.meta_range, kmem.bits_range, kmem.zone_range)
        )

    def lookup(self, address):
        kmem = self.kmem

        if kmem.meta_range.contains(address):
            return ZonePageMetadata(self.kmem, address)

        if kmem.bits_range.contains(address):
            return ZoneBitsMemoryObject(self.kmem, address)

        return ZoneHeapMemoryObject(self.kmem, address)


class ZPercpuValue(object):
    """
    Provides an enumerator for a zpercpu value
    """

    def __init__(self, sbvalue):
        """
        @param sbvalue (SBValue)
            The value to enumerate
        """
        self.sbv = sbvalue

    def __iter__(self):
        sbv  = self.sbv
        kmem = KMem.get_shared()
        addr = sbv.GetValueAsAddress()
        name = sbv.GetName()
        ty   = sbv.GetType().GetPointeeType()

        return (
            sbv.xCreateValueFromAddress(name, addr + (cpu << kmem.page_shift), ty)
            for cpu in kmem.zcpus
        )


class Zone(object):
    """
    the Zone class wraps XNU Zones and provides fast enumeration
    of allocated, cached, ... elements.
    """

    def __init__(self, index_name_or_addr):
        """
        @param index_name_or_addr (int or str):
            - int: a zone index within [0, num_zones)
            - int: a zone address within [zone_array, zone_array + num_zones)
            - str: a zone name

        @param kmem (KMem or None)
            The kmem this command applies to,
            or None for the current one
        """

        kmem = KMem.get_shared()
        zarr = kmem.zone_array

        if isinstance(index_name_or_addr, str):
            mangled_name = index_name_or_addr.replace(' ', '.')
            zid = self._find_zone_id_by_mangled_name(mangled_name)
        elif index_name_or_addr <= kmem.num_zones:
            zid = index_name_or_addr
        else:
            zid = index_name_or_addr - zarr.GetLoadAddress()
            zid = zid // zarr.GetType().GetArrayElementType().GetByteSize()

        self.kmem = kmem
        self.zid  = zid
        self.sbv  = zarr.chkGetChildAtIndex(zid)

    @staticmethod
    @caching.cache_dynamically
    def get_zone_name(zid, target=None):
        """
        Returns a zone name by index.

        @param zid (int
            A zone ID

        @returns (str or None)
            Returns a string holding the zone name
            if the zone exists, or None
        """

        kmem = KMem.get_shared()
        if zid >= kmem.num_zones:
            return None

        zone = kmem.zone_array.chkGetChildAtIndex(zid)
        zsec = kmem.zsec_array.chkGetChildAtIndex(zid)

        if zone.xGetIntegerByName('z_self') == 0:
            return None

        heap_id = zsec.xGetIntegerByName('z_kheap_id')

        return KMem._HEAP_NAMES[heap_id] + zone.xGetCStringByName('z_name')

    @staticmethod
    @caching.cache_dynamically
    def _find_zone_id_by_mangled_name(name, target=None):
        """
        Lookup a zone ID by name

        @param name (str)
            The name of the zone to lookup

        @returns (int)
            The zone ID for this name
        """

        kmem = KMem.get_shared()
        for zid in range(kmem.num_zones):
            k = Zone.get_zone_name(zid)
            if k is not None and name == k.replace(' ', '.'):
                return zid

        raise KeyError("No zone called '{}' found".format(name))

    @property
    def initialized(self):
        """ The zone name """

        return self.sbv.xGetIntegerByName('z_self') != 0

    @property
    def address(self):
        """ The zone address """

        return self.sbv.GetLoadAddress()

    @property
    def name(self):
        """ The zone name """

        return self.get_zone_name(self.zid)

    @property
    def mangled_name(self):
        """ The zone mangled name """

        return self.name.replace(' ', '.')

    @caching.dyn_cached_property
    def elem_redzone(self, target=None):
        """ The inner size of elements """

        if self.kmem.kasan_classic:
            return self.sbv.xGetIntegerByName('z_kasan_redzone')
        return 0

    @caching.dyn_cached_property
    def elem_inner_size(self, target=None):
        """ The inner size of elements """

        return self.sbv.xGetIntegerByName('z_elem_size')

    @caching.dyn_cached_property
    def elem_outer_size(self, target=None):
        """ The size of elements """

        if not self.kmem.kasan_classic:
            return self.elem_inner_size
        return self.elem_inner_size + self.elem_redzone

    @caching.dyn_cached_property
    def elem_inner_offs(self, target=None):
        """ The chunk initial offset """

        return self.sbv.xGetIntegerByName('z_elem_offs')

    @caching.dyn_cached_property
    def chunk_pages(self, target=None):
        """ The number of pages per chunk """

        return self.sbv.xGetIntegerByName('z_chunk_pages')

    @caching.dyn_cached_property
    def chunk_elems(self, target=None):
        """ The number of elements per chunk """

        return self.sbv.xGetIntegerByName('z_chunk_elems')

    @property
    def percpu(self):
        """ Whether this is a per-cpu zone """

        return self.sbv.xGetIntegerByName('z_percpu')

    @property
    def btlog(self):
        """ Returns the zone's BTLog or None """

        try:
            btlog = self.sbv.xGetPointeeByName('z_btlog')
            return BTLog(btlog)
        except:
            return None

    def describe(self):
        kmem = self.kmem
        zone = self.sbv
        zsec = kmem.zsec_array.chkGetChildAtIndex(self.zid)

        submap_arr  = kmem.target.chkFindFirstGlobalVariable('zone_submaps_names')
        submap_idx  = zsec.xGetIntegerByName('z_submap_idx')
        submap_name = submap_arr.xGetCStringAtIndex(submap_idx)
        submap_end  = zsec.xGetIntegerByName('z_submap_from_end')

        try:
            btlog = zone.xGetIntegerByName('z_btlog')
        except:
            # likely a release kernel
            btlog = None

        fmt = (
            "Zone Info\n"
            " name                 : {0.name} ({&z:#x})\n"
            " submap               : {1} (from {2})\n"
            " element size         : {0.elem_inner_size}\n"
            " element offs         : {0.elem_inner_offs}\n"
        )
        if kmem.kasan_classic:
            fmt += " element redzone      : {0.elem_redzone}\n"
        fmt += " chunk elems / pages  : {$z.z_chunk_elems} / {$z.z_chunk_pages}\n"
        if btlog:
            fmt += " btlog                : {$z.z_btlog:#x}\n"

        print(xnu_format(fmt, self, submap_name,
            "right" if submap_end else "left", z = zone));

    def iter_page_queue(self, name):
        kmem = self.kmem
        zone = self.sbv

        pva = zone.xGetIntegerByPath('.{}.packed_address'.format(name))

        while pva:
            meta = ZonePageMetadata._create_with_pva(kmem, pva)
            pva  = meta.next_pva
            yield meta

    def _depotElements(self, depot, into):
        last   = depot.xGetPointeeByName('zd_tail').GetValueAsAddress()
        mag    = depot.xGetPointeeByName('zd_head')

        kmem   = self.kmem
        n      = kmem.mag_size
        target = kmem.target

        while mag and mag.GetLoadAddress() != last:
            into.update(kmem.iter_addresses(target.xIterAsULong(
                mag.xGetLoadAddressByName('zm_elems'),
                n
            )))
            mag = mag.xGetPointeeByName('zm_next')

        return into

    def cached(self, into = None):
        """ all addresses in per-cpu caches or per-cpu depots """

        pcpu = self.sbv.GetChildMemberWithName('z_pcpu_cache')
        into = into if into is not None else set()

        if pcpu.GetValueAsAddress():
            target = pcpu.target
            kmem   = self.kmem

            for cache in ZPercpuValue(pcpu):
                into.update(kmem.iter_addresses(target.xIterAsULong(
                    cache.xGetIntegerByName('zc_alloc_elems'),
                    cache.xGetIntegerByName('zc_alloc_cur')
                )))

                into.update(kmem.iter_addresses(target.xIterAsULong(
                    cache.xGetIntegerByName('zc_free_elems'),
                    cache.xGetIntegerByName('zc_free_cur')
                )))

                self._depotElements(
                    cache.chkGetChildMemberWithName('zc_depot'),
                    into = into
                )

        return into

    def recirc(self, into = None):
        """ all addresses in the recirculation layer """

        return self._depotElements(
            self.sbv.chkGetChildMemberWithName('z_recirc'),
            into = into if into is not None else set()
        )

    def iter_all(self, ty = None):
        """
        Returns a generator for all addresses/values that can be made

        @param ty (SBType or None)
            An optional type to use to form SBValues

        @returns
            - (generator<int>) if ty is None
            - (generator<SBValue>) if ty is set
        """

        addresses = (
            addr
            for name in (
                'z_pageq_full',
                'z_pageq_partial',
                'z_pageq_empty',
            )
            for meta in self.iter_page_queue(name)
            for addr in meta.iter_all(self)
        )

        if ty is None:
            return addresses

        fn = self.kmem.target.xCreateValueFromAddress
        return (fn('e', addr, ty) for addr in addresses)

    def iter_free(self, ty = None):
        """
        Returns a generator for all free addresses/values

        @param ty (SBType or None)
            An optional type to use to form SBValues

        @returns
            - (generator<int>) if ty is None
            - (generator<SBValue>) if ty is set
        """

        cached = set()
        self.cached(into = cached)
        self.recirc(into = cached)

        addresses = (
            addr
            for name in (
                'z_pageq_full',
                'z_pageq_partial',
            )
            for meta in self.iter_page_queue(name)
            for addr in meta.iter_all(self)
            if  addr in cached or not meta.is_allocated(self, addr)
        )

        if ty is None:
            return addresses

        fn = self.kmem.target.xCreateValueFromAddress
        return (fn('e', addr, ty) for addr in addresses)

    def iter_allocated(self, ty = None):
        """
        Returns a generator for all allocated addresses/values

        @param ty (SBType or None)
            An optional type to use to form SBValues

        @returns
            - (generator<int>) if ty is None
            - (generator<SBValue>) if ty is set
        """

        cached = set()
        self.cached(into = cached)
        self.recirc(into = cached)

        addresses = (
            addr
            for name in (
                'z_pageq_full',
                'z_pageq_partial',
            )
            for meta in self.iter_page_queue(name)
            for addr in meta.iter_allocated(self)
            if  addr not in cached
        )

        if ty is None:
            return addresses

        fn = self.kmem.target.xCreateValueFromAddress
        return (fn('e', addr, ty) for addr in addresses)

    def __iter__(self):
        return self.iter_allocated()


__all__ = [
    ZPercpuValue.__name__,
    Zone.__name__,
]
