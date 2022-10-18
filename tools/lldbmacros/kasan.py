from __future__ import absolute_import, division, print_function

from six import add_metaclass
from abc import ABCMeta, abstractmethod
from builtins import range
from collections import namedtuple
import itertools

from xnu import *
from utils import *
from core.configuration import *

ShadowMapEntry = namedtuple('ShadowMapEntry', ['addr', 'shaddr', 'value'])


@add_metaclass(ABCMeta)
class AbstractShadowMap(object):
    """ An abstract class serving as a template for KASan variant specific
        shadow map implementations.
    """

    def __init__(self, base, scale):
        self._base = base
        self._scale = scale

    @abstractmethod
    def address(self, shaddr):
        """ Returns an address for a given shadow address. """
        pass

    @abstractmethod
    def shadow_address(self, addr):
        """ Returns a shadow address for a given address. """
        pass

    @abstractmethod
    def resolve(self, addr, is_shadow=False):
        """ Returns an address, a shadow address and a respective value
            retrieved from a shadow map.
        """
        pass

    @property
    def base(self):
        """ Returns a shadow map base. """
        return self._base

    @property
    def scale(self):
        """ Returns a scale size. """
        return self._scale

    @property
    def granule_size(self):
        """ Returns a granule size. """
        return 1 << self.scale

    @property
    def kexts_loaded(self):
        return unsigned(kern.globals.kexts_loaded)

    def page_range(self):
        pbase = unsigned(kern.globals.shadow_pbase)
        ptop = unsigned(kern.globals.shadow_ptop)
        pnext = unsigned(kern.globals.shadow_pnext)
        return (pbase, ptop, pnext)

    def page_usage(self):
        pages_used = unsigned(kern.globals.shadow_pages_used)
        pages_total = unsigned(kern.globals.shadow_pages_total)
        return (pages_used, pages_total)

    def next_addr(self, addr):
        """ Returns an address corresponding to a next shadow map byte. """
        return addr + self.granule_size

    def prev_addr(self, addr):
        """ Returns an address corresponding to a previous shadow map byte. """
        return addr - self.granule_size

    def get(self, shaddr):
        """ Returns a value from a shadow map at given shadow address. """
        try:
            return unsigned(kern.GetValueFromAddress(shaddr, 'uint8_t *')[0])
        except:
            raise ValueError("No shadow mapping for 0x{:x}".format(shaddr))

    def iterator(self, addr, count, step=1):
        """ Returns an iterator to walk through a specified area of KASan
            shadow map.
        """
        step *= self.granule_size
        return (self.resolve(addr + d)
                for d in range(0, count
                               if step > 0 else -count, step))

    def dropwhile(self, drop_cond, addr, count, step=1):
        """ Returns an iterator to walk through a specified area of KASan
            shadow map. The iterator drops elements as long as the predicate is true.
            Afterwards, returns every element.
        """
        return itertools.dropwhile(drop_cond, self.iterator(addr, count, step))


class MTEShadowMap(AbstractShadowMap):
    """ Implements a MTESan shadow map providing access to the map content. """
    MTE_MASK = 0x0F00000000000000
    TBI_MASK = 0xFF00000000000000
    TBI_SHIFT = 56

    @staticmethod
    def create():
        base = getattr(kern.globals, '__asan_shadow_memory_dynamic_address')
        return MTEShadowMap(base, 4)

    def address(self, shaddr):
        addr = (shaddr - self._base) << self._scale
        return self.set_mte(addr, self.get(shaddr))

    def shadow_address(self, addr):
        return self._base + (self.clr_tbi(addr) >> self._scale)

    def resolve(self, addr, is_shadow=False):
        if is_shadow:
            shaddr = addr
            tag = self.get(shaddr)
            addr = self.address(shaddr)
        else:
            shaddr = self.shadow_address(addr)
            # Fix the address tag in case it was not correct
            # and preserve the rest of TBI.
            tag = self.get(shaddr)
            addr = self.set_mte(addr, tag)
        return ShadowMapEntry(addr, shaddr, tag)

    @staticmethod
    def set_mte(addr, tag):
        """ Sets a given address MTE tag. """
        tag = (tag << MTEShadowMap.TBI_SHIFT) & MTEShadowMap.MTE_MASK
        return (addr & ~MTEShadowMap.MTE_MASK) | tag

    @staticmethod
    def clr_tbi(addr):
        """ Strips a given address TBI. """
        return addr | MTEShadowMap.TBI_MASK


class ClassicShadowMap(AbstractShadowMap):
    """ Implements a KASan Classic shadow map providing access to the map content. """
    @staticmethod
    def create():
        base = getattr(kern.globals, '__asan_shadow_memory_dynamic_address')
        return ClassicShadowMap(base, 3)

    def address(self, shadow_addr):
        return (shadow_addr - self._base) << self._scale

    def shadow_address(self, addr):
        return self._base + (addr >> self._scale)

    def resolve(self, addr, is_shadow=False):
        if is_shadow:
            shaddr = addr
            addr = self.address(shaddr)
        else:
            shaddr = self.shadow_address(addr)
        return ShadowMapEntry(addr, shaddr, self.get(shaddr))


class MemObject(object):
    """ Represents a plain memory object. """

    def __init__(self, mo_type, base, size, redzones):
        self._base = base
        self._size = size
        self._mo_type = mo_type
        self._redzones = redzones

    @property
    def type(self):
        """ Returns a memory object type string. """
        return self._mo_type

    @property
    def zone(self):
        """ Returns a zone this memory object is allocated in. """
        return None

    def total_alloc(self):
        """ Returns an address and a size of the allocation, including redzones. """
        return self.valid_alloc()

    def valid_alloc(self):
        """ Returns an address and a size of the allocation, without redzones. """
        return (self._base, self._size)

    def redzones(self):
        """ Returns a tuple of redzone sizes. """
        return self._redzones

    def backtrace(self):
        """ Returns the latest known backtrace recorded for a given address. """
        return None


class AllocHeapMemObject(object):
    """ Represents a memory object allocated on a heap. """
    alloc_header_sz = 16

    def __init__(self, hdr, ftr):
        self._hdr = hdr
        self._ftr = ftr

    @property
    def type(self):
        """ Returns a memory object type string. """
        return "heap"

    @property
    def zone(self):
        """ Returns a zone this memory object is allocated in. """
        return None

    def total_alloc(self):
        """ Returns an address and a size of the allocation, including redzones. """
        return (self._alloc_base(), unsigned(self._hdr.alloc_size))

    def valid_alloc(self):
        return (self._valid_base(), unsigned(self._hdr.user_size))

    def redzones(self):
        """ Returns a tuple of redzone sizes. """
        left_rz = unsigned(self._hdr.left_rz)
        right_rz = unsigned(self._hdr.alloc_size) - unsigned(
            self._hdr.user_size) - left_rz
        return (left_rz, right_rz)

    def backtrace(self):
        """ Returns the latest known backtrace recorded for a given address. """
        slide = unsigned(kern.globals.vm_kernel_slid_base)
        n = unsigned(self._hdr.frames)
        return (slide + unsigned(self._ftr.backtrace[i]) for i in range(0, n))

    def _valid_base(self):
        return unsigned(self._hdr) + self.alloc_header_sz

    def _alloc_base(self):
        return self._valid_base() - unsigned(self._hdr.left_rz)


class FreeHeapMemObject(object):
    """ Represents a memory object allocated on a heap. """

    def __init__(self, hdr):
        self._hdr = hdr

    @property
    def type(self):
        """ Returns a memory object type string. """
        mo_type = "heap:kalloc"
        if self.zone:
            mo_type = "heap:zone"
            if str(self.zone.z_name).startswith("fakestack"):
                mo_type = "stack"
        return mo_type

    @property
    def zone(self):
        """ Returns a zone this memory object is allocated in. """
        return self._hdr.zone

    def total_alloc(self):
        """ Returns an address and a size of the allocation, including redzones. """
        return (unsigned(self._hdr), unsigned(self._hdr.size))

    def valid_alloc(self):
        """ Returns an address and a size of the allocation, without redzones. """
        left_rz, _ = self.redzones()
        return (unsigned(self._hdr) + left_rz, unsigned(self._hdr.user_size))

    def redzones(self):
        """ Returns a tuple of redzone sizes. """
        rzsz = self._hdr.size - self._hdr.user_size
        left_rz = 16

        if self._hdr.zone:
            if str(self._hdr.zone.z_name).startswith("fakestack"):
                left_rz = unsigned(self._hdr.zone.z_kasan_redzone)
        else:
            pgsz = unsigned(kern.globals.page_size)
            if rzsz >= 2 * pgsz:
                left_rz = pgsz

        return (left_rz, rzsz - left_rz)

    def backtrace(self):
        """ Returns the latest known backtrace recorded for a given address. """
        slide = unsigned(kern.globals.vm_kernel_slid_base)
        n = unsigned(self._hdr.frames)
        return (slide + unsigned(self._hdr.backtrace[i]) for i in range(0, n))


class MTEMemObject(object):
    """ Represents an allocated or freed memory object. """

    def __init__(self, addr, zone):
        self._addr = addr
        self._zone = zone
        self._btlib = BTLibrary()

    @property
    def type(self):
        """ Returns a memory object type string. """
        return "zone"

    @property
    def zone(self):
        """ Returns a zone this memory object is allocated in. """
        return self._zone

    def valid_alloc(self):
        """ Returns an address and a size of the allocation, without redzones. """
        return self.total_alloc()

    def total_alloc(self):
        """ Returns an address and a size of the allocation, including redzones. """
        return (self._addr, unsigned(self._zone.z_elem_size))

    def redzones(self):
        """ Returns a tuple of redzone sizes. """
        return (0, 0)

    def backtrace(self):
        """ Returns the latest known backtrace recorded for a given address. """
        if not self._zone.z_btlog_kasan:
            return None
        btlog = BTLog(unsigned(self._zone.z_btlog_kasan))
        # Addresses are normalized (TBI stripped) in BT logs.
        stripped_addr = MTEShadowMap.clr_tbi(self._addr)
        records = btlog.iter_records(wantElement=stripped_addr, reverse=True)
        record = next(records, None)
        if not record or record[3] == 0:
            return None
        return (f for f in self._btlib.get_stack(record[3]).frames())


class MTEMemObjectProvider(object):
    """ Allows to find and create memory objects on MTESan variant. """

    def __init__(self, shadow_map):
        self._sm = shadow_map

    def lookup(self, addr):
        """  Finds and creates a memory object around given address. """
        stripped_addr = MTEShadowMap.clr_tbi(addr)
        z_meta = ZoneMeta(stripped_addr)
        if not z_meta or not z_meta.zone:
            raise ValueError("Address 0x{:x} not found in zones".format(addr))
        sme = self._sm.resolve(z_meta.getElementAddress(stripped_addr))
        return MTEMemObject(sme.addr, z_meta.zone)


class ClassicMemObjectProvider(object):
    """ Allows to find and create memory objects on kasan variant. """
    LIVE_XOR = 0x3a65
    FREE_XOR = 0xf233

    def __init__(self, shadow_map):
        self._sm = shadow_map

    def lookup(self, addr):
        """  Finds and creates a memory object around given address. """
        return self._create_mo(addr)

    def _create_mo(self, addr):
        area = 32 * 1024
        sme = self._sm.resolve(addr)

        if sme.value == 0xfa:
            it = self._sm.dropwhile(lambda a: a.value == 0xfa, addr, area)
            return self._create_heap_mo(next(it).addr)
        elif sme.value == 0xfb:
            it = self._sm.dropwhile(lambda a: a.value != 0xfa, addr, area, -1)
            return self._create_heap_mo(self._sm.next_addr(next(it).addr))

        inner_object_tags = {0, 1, 2, 3, 4, 5, 6, 7, 0xf8}

        if sme.value not in inner_object_tags:
            # We could do better here and try to find the object,
            # instead of just saying it is poisoned.
            return sme

        def consume_until(it, stop_condition, arg):
            for value in it:
                stop, arg = stop_condition(arg, value)
                if stop:
                    return arg
            raise StopIteration

        def sum_and_skip(prev, new):
            mo_base, mo_size = prev
            if new.value not in inner_object_tags:
                return (True, (mo_base, mo_size, new.value))
            mo_size += 8 - new.value if new.value == 0xf8 else 8
            return (False, (new.addr, mo_size))

        # Find memory object beginning.
        try:
            it = self._sm.iterator(self._sm.prev_addr(addr), area, -1)
            mo_base, mo_size, left_rz = consume_until(it, sum_and_skip,
                                                      (addr, 0))
        except StopIteration:
            raise ValueError("Cannot find left redzone")

        if left_rz == 0xfa:
            return self._create_heap_mo(mo_base)

        # Next candidates: fakestack and global objects
        if left_rz not in {0xf1, 0xf2, 0xf9}:
            raise ValueError("Unknown left redzone 0x{:x}".format(left_rz))

        # Find memory object end.
        try:
            it = self._sm.iterator(addr, area)
            _, mo_size, right_rz = consume_until(it, sum_and_skip,
                                                 (addr, mo_size))
        except StopIteration:
            raise ValueError("Cannot find right redzone")

        if right_rz == 0xf9:
            return MemObject("global", mo_base, mo_size, None)
        elif left_rz in {0xf1, 0xf2}:
            return MemObject("stack", mo_base, mo_size, None)
        else:
            raise ValueError(
                "Unknown redzone combination: 0x{:x}, 0x{:x}".format(
                    left_rz, right_rz))

    def _create_heap_mo(self, raw_addr):
        addr = (raw_addr & ~0x7)

        def magic_for_addr(addr, xor):
            magic = addr & 0xffff
            magic ^= (addr >> 16) & 0xffff
            magic ^= (addr >> 32) & 0xffff
            magic ^= (addr >> 48) & 0xffff
            magic ^= xor
            return magic

        alloc_hdr = kern.GetValueFromAddress(
            addr - AllocHeapMemObject.alloc_header_sz,
            'struct kasan_alloc_header *')
        free_hdr = kern.GetValueFromAddress(addr, 'struct freelist_entry *')

        if magic_for_addr(addr, self.LIVE_XOR) == unsigned(alloc_hdr.magic):
            base = addr - alloc_hdr.left_rz
            if base <= addr < (base + alloc_hdr.alloc_size):
                addr += alloc_hdr.user_size
                footer = kern.GetValueFromAddress(
                    addr, 'struct kasan_alloc_footer *')
                return AllocHeapMemObject(alloc_hdr, footer)
        elif magic_for_addr(addr, self.FREE_XOR) == unsigned(free_hdr.magic):
            if addr <= raw_addr < addr + free_hdr.size:
                return FreeHeapMemObject(free_hdr)

        raise ValueError("No heap allocation found at 0x{:x}".format(raw_addr))


@add_metaclass(ABCMeta)
class AbstractKasan(object):
    """ KASan abstract class serving as a template for respective KASan implementations. """
    CTLTYPE = 0xf
    CTLTYPE_NODE = 0x1
    CTLTYPE_INT = 0x2
    CTLTYPE_STRING = 0x3
    _sysctls = None

    def __init__(self, kasan_variant, shadow_map, mo_provider):
        self._kasan_variant = kasan_variant
        self._sm = shadow_map
        self._mo_provider = mo_provider

    @abstractmethod
    def from_shadow(self, saddr):
        """ Prints an address for a given shadow address. """
        sme = self._sm.resolve(saddr, True)
        print("0x{:016x}".format(sme.addr))

    @abstractmethod
    def to_shadow(self, addr):
        """ Prints a shadow address for a given address. """
        sme = self._sm.resolve(addr, False)
        print("0x{:016x}".format(sme.shaddr))

    @abstractmethod
    def shadow(self, addr, line_count):
        """ Prints content of a shadow map respective to a given address. """
        sme = self._sm.resolve(addr, False)
        print("0x{:02x} @ 0x{:016x} [{}]\n\n".format(sme.value, sme.shaddr,
                                                     self.tag_name(sme.value)))
        self._print_shadow_map(sme.shaddr, line_count)

    @abstractmethod
    def whatis(self, addr):
        """ Prints KASan records for a memory object at a given address. """
        pass

    @abstractmethod
    def heap(self, addr):
        """ Prints KASan records for a heap memory object at a given address. """
        pass

    @abstractmethod
    def quarantine(self, qtype, addrs, n=None, show_bt=False, O=None):
        """ Prints KASan quarantined addresses.

            qtype:
                Quarantine type
            addrs:
                List of addresses to look up in quarantine
            n:
                Number of shown quarantined addresses.
                Searches from a quarantine head if positive, from the end if negative.
            show_bt:
                Include backtraces in a listing.
        """
        pass

    @abstractmethod
    def legend(self):
        """ Prints a shadow map tags legend. """
        pass

    @abstractmethod
    def tag_name(self, tag):
        """ Returns a textual description of a shadow map tag. """
        pass

    def info(self):
        """ Prints overal KASan information. """
        nkexts = self._sm.kexts_loaded
        pbase, ptop, pnext = self._sm.page_range()
        pages_used, pages_total = self._sm.page_usage()

        print("{:<21s}: {:>s}".format("Model", self._kasan_variant))
        print("{:<21s}: {:>d} (1:{})".format("Scale", self._sm.scale,
                                             1 << self._sm.scale))
        print("{:<21s}: 0x{:016x}".format("Shadow Offset", self._sm.base))
        print("{:<21s}: 0x{:x}-0x{:x}".format("Shadow Pages", pbase, ptop))
        print("{:<21s}: 0x{:x}".format("Shadow RO Valid Page", pbase))
        print("{:<21s}: 0x{:x}".format("Shadow Next Page", pnext))
        print("{:<21s}: {} of {} pages ({:.1f}%)".format("Shadow Utilization",
                                                         pages_used, pages_total, 100.0 * pages_used / pages_total))

        print("{:<21s}: {:d}".format(
            "Stacks Instrumented", 0 if self._sysctl("light") else 1))
        print("{:<21s}: {:d}".format(
            "Zalloc Integration", self._sysctl("zalloc")))
        print("{:<21s}: {:d}".format(
            "Kalloc Integration", self._sysctl("kalloc")))
        print("{:<21s}: {:d}".format(
            "Dynamic Exclude List", self._sysctl("dynamicbl")))
        print("{:<21s}: {:d}".format("Kexts Loaded", nkexts))
        print("{:<21s}: {:d}".format("Debug", self._sysctl("debug")))

    def command(self, cmd, args, opts, O):
        """ Executes entered "kasan" macro subcommand. """
        if cmd in ['a2s', 'toshadow', 'fromaddr', 'fromaddress']:
            if not args:
                raise ArgumentError("Missing address argument")
            self.to_shadow(int(args[0], 0))
        elif cmd in ['s2a', 'toaddr', 'toaddress', 'fromshadow']:
            if not args:
                raise ArgumentError("Missing address argument")
            self.from_shadow(int(args[0], 0))
        elif cmd == 'shadow':
            if not args:
                raise ArgumentError("Missing address argument")
            self.shadow(int(args[0], 0), int(opts.get("-C", 1)))
        elif cmd == 'whatis':
            if not args:
                raise ArgumentError("Missing address argument")
            self.whatis(int(args[0], 0))
        elif cmd in ['alloc', 'heap']:
            if not args:
                raise ArgumentError("Missing address argument")
            self.heap(int(args[0], 0))
        elif cmd == "quarantine":
            qtype = opts.get("-T", "zalloc")
            addrs = set(int(arg, base=16) for arg in args) if args else None
            count = int(opts.get("-C")) if "-C" in opts else None
            if addrs and count:
                raise ArgumentError(
                    "Address list and -C are mutually exclusive")
            show_bt = "-S" in opts
            self.quarantine(qtype, addrs, n=count, show_bt=show_bt, O=O)
        elif cmd == 'info':
            self.info()
        elif cmd in ('key', 'legend'):
            self.legend()
        else:
            raise ArgumentError("Unknown subcommand: `{}'".format(cmd))

    @classmethod
    def _sysctl(cls, name, default=None):
        """Returns a value of kern.kasan.<name>, a default value if not found."""
        if not cls._sysctls:
            # Let's cache sysctls, as getting them is fairly expensive.
            cls._sysctls = cls._load_sysctls()
        return cls._sysctls.get(name, default)

    @staticmethod
    def _load_sysctls():
        """ Loads all kern.kasan.<name> values. Strings and unsigned
            integers are needed and supported only.
        """
        def get_value(a, t): return kern.GetValueFromAddress(unsigned(a), t)
        def prop_type(p): return p.oid_kind & AbstractKasan.CTLTYPE

        def prop_value(prop):
            if prop_type(prop) == AbstractKasan.CTLTYPE_INT:
                if not prop.oid_arg1:
                    return prop.oid_arg2
                return dereference(get_value(prop.oid_arg1, 'unsigned *'))
            assert(prop_type(prop) == AbstractKasan.CTLTYPE_STRING)
            return get_value(prop.oid_arg1, 'char *') if prop.oid_arg1 else None

        return {
            str(p[0].oid_name): prop_value(p[0])
            for p in IterateSysctls(kern.globals.sysctl__children, "kern.kasan")
            if prop_type(p[0]) != AbstractKasan.CTLTYPE_NODE
        }

    def _print_shadow_map(self, shadow_addr, lines_around=1, line_width=16):
        base = self._sm.address((shadow_addr & ~0xf) -
                                line_width * lines_around)
        scope = 2 * self._sm.granule_size * (
            (line_width * lines_around) + line_width)
        print_area = self._sm.iterator(base, scope)
        line = ""

        print(" " * 19 + "  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f")
        for i, (_, shaddr, value) in enumerate(print_area):
            if i % line_width == 0:
                if i > 0:
                    space = "" if base == shadow_addr else " "
                    print("0x{:x}:{}{}".format(shaddr - line_width, space,
                                               line))
                line = ""
                base = shaddr
            lr = ("", " ")
            if shaddr == shadow_addr:
                lr = ("[", "]")
            elif (shaddr + 1) == shadow_addr:
                lr = ("", "")
            line += "{}{:02x}{}".format(lr[0], value, lr[1])

    def _print_mo(self, mo, addr):
        print("Object Info:")

        mo_base, mo_size = mo.valid_alloc()
        print(" Valid range: 0x{:x} -- 0x{:x} ({} bytes)".format(
            mo_base, mo_base + mo_size - 1, mo_size))

        mo_base, mo_size = mo.total_alloc()
        print(" Total range: 0x{:x} -- 0x{:x} ({} bytes)".format(
            mo_base, mo_base + mo_size - 1, mo_size))

        if mo.redzones():
            left_rz, right_rz = mo.redzones()
            print(" Redzones:    {} / {} bytes".format(left_rz, right_rz))

        print(" Type:        {}".format(mo.type.capitalize()))
        if mo.zone:
            print(" Zone:        0x{:x} ({:s})".format(unsigned(mo.zone),
                                                       mo.zone.z_name))

        print(" \n")
        sme = self._sm.resolve(addr)
        print("Address Info:")
        print(" Address:     0x{:x} (Shadow: 0x{:x})".format(
            sme.addr, sme.shaddr))
        print(" Tag:         0x{:X} ({})".format(sme.value,
                                                 self.tag_name(sme.value)))
        print(" Offset:      {:d} (Remains: {:d} bytes)".format(
            addr - mo_base, mo_base + mo_size - addr))

        frames = mo.backtrace()
        if frames:
            print(" \n")
            print("(De)Allocation Backtrace:")
            for frame in frames:
                print(" {}".format(GetSourceInformationForAddress(frame)))
            print("", end=' ')

        self._print_mo_content(mo_base, mo_size, 1)

    def _print_mo_content(self, base, size, ctx):
        size = max(size, 16)
        base -= base % 16
        start = base - 16 * ctx
        size += size % 16
        size = min(size + 16 * 2 * ctx, 256)

        try:
            data_array = kern.GetValueFromAddress(start, "uint8_t *")
            print(" \n")
            print_hex_data(data_array[0:size], start, "Object Memory Dump")
        except Exception as e:
            print("Object content not available: {}".format(e))


class ClassicKasan(AbstractKasan):
    """ Provides KASan Classic specific implementation of kasan commands. """
    GUARD_SIZE = 16
    QUARANTINE_TYPES = {
        "zalloc": 0,
        "kalloc": 1,
        "fakestack": 2
    }
    _shadow_strings = {
        0x00: 'VALID',
        0x01: 'PARTIAL1',
        0x02: 'PARTIAL2',
        0x03: 'PARTIAL3',
        0x04: 'PARTIAL4',
        0x05: 'PARTIAL5',
        0x06: 'PARTIAL6',
        0x07: 'PARTIAL7',
        0xac: 'ARRAY_COOKIE',
        0xf0: 'STACK_RZ',
        0xf1: 'STACK_LEFT_RZ',
        0xf2: 'STACK_MID_RZ',
        0xf3: 'STACK_RIGHT_RZ',
        0xf5: 'STACK_FREED',
        0xf8: 'STACK_OOSCOPE',
        0xf9: 'GLOBAL_RZ',
        0xe9: 'HEAP_RZ',
        0xfa: 'HEAP_LEFT_RZ',
        0xfb: 'HEAP_RIGHT_RZ',
        0xfd: 'HEAP_FREED'
    }

    @staticmethod
    def create():
        base = getattr(kern.globals, '__asan_shadow_memory_dynamic_address')
        shadow_map = ClassicShadowMap(base, 3)
        mo_provider = ClassicMemObjectProvider(shadow_map)
        return ClassicKasan(shadow_map, mo_provider)

    def __init__(self, shadow_map, mo_provider):
        super(ClassicKasan, self).__init__(
            "kasan-classic", shadow_map, mo_provider)

    def from_shadow(self, saddr):
        super(ClassicKasan, self).from_shadow(saddr)

    def to_shadow(self, addr):
        super(ClassicKasan, self).to_shadow(addr)

    def shadow(self, addr, line_count):
        super(ClassicKasan, self).shadow(addr, line_count)

    def whatis(self, addr):
        mo = self._mo_provider.lookup(addr & ~0x7)
        if isinstance(mo, ShadowMapEntry):
            print("Poisoned memory: shadow address: 0x{:x}, "
                  "tag: 0x{:X} ({:s})".format(mo.shaddr, mo.value,
                                              self.tag_name(mo.value)))
            return
        self._print_mo(mo, addr)

    def heap(self, addr):
        mo = self._mo_provider.lookup(addr & ~0x7)
        if mo.type.startswith("heap"):
            self._print_mo(mo, addr)
        else:
            print("Not a heap object")

    def quarantine(self, qtype, addrs=None, n=None, show_bt=False, O=None):
        qitems = self.quarantined(qtype)
        if n:
            from_tail = n < 0
            qitems = list(qitems)
            n = min(abs(n), len(qitems))
            qitems = qitems[-n:] if from_tail else qitems[:n]
        elif addrs:
            qitems = (qi for qi in qitems if unsigned(qi) in addrs)
        self._print_quarantined(qitems, show_bt, O)

    def legend(self):
        for k in self._shadow_strings:
            print(" {:02x}: {:s}".format(k, self._shadow_strings[k]))

    def tag_name(self, tag):
        return self._shadow_strings.get(tag, 'Unknown')

    @staticmethod
    def quarantined(qtype):
        """Returns an iterator of memory addresses from a given quarantine.
        Possible quarantine types are: `"zalloc"`, `"kalloc"` and `"fakestack"`. """
        try:
            q = kern.globals.quarantines[ClassicKasan.QUARANTINE_TYPES[qtype]]
        except:
            raise ArgumentError("Unknown quarantine type: {}".format(qtype))
        return IterateTAILQ_HEAD(addressof(q.freelist), "list", 's')

    @staticmethod
    def _print_quarantined(qitems, show_bt, O):
        """ Formats and prints quarantine entries. Includes a backtrace
            if `show_bt` is `True`.
        """
        qitems_hdr = "{:>16s} {:>5s} {:>4s} {:>9s} {:>8s} {:>16s}".format(
            "ADDRESS", "MAGIC", "CRC", "USER_SIZE", "SIZE", "ZONE")
        qitem_hdr = (
            "{addr:>16x} {e.magic:>05x} {e.crc:>04x} "
            "{e.user_size:>9d} {e.size:>8d} {e.zone:>16x} ({zname:>s})"
        )

        if not show_bt:
            with O.table(qitems_hdr):
                for qitem in qitems:
                    zname = qitem.zone.z_name if qitem.zone else "not in zone"
                    print(qitem_hdr.format(addr=unsigned(qitem),
                                           e=qitem, zname=zname))
            return

        for qitem in qitems:
            print("  ")
            with O.table(qitems_hdr):
                zname = qitem.zone.z_name if qitem.zone else "not in zone"
                print(qitem_hdr.format(addr=unsigned(qitem),
                                       e=qitem, zname=zname))
            print("  ")
            for frame in FreeHeapMemObject(qitem).backtrace():
                print("\t{}".format(GetSourceInformationForAddress(frame)))


class MTESan(AbstractKasan):
    """ Provides MTESan specific implementation of kasan commands. """
    @staticmethod
    def create():
        shadow_map = MTEShadowMap.create()
        mo_provider = MTEMemObjectProvider(shadow_map)
        return MTESan(shadow_map, mo_provider)

    def __init__(self, shadow_map, mo_provider):
        super(MTESan, self).__init__("kasan-tbi", shadow_map, mo_provider)
        pass

    def from_shadow(self, saddr):
        super(MTESan, self).from_shadow(saddr)

    def to_shadow(self, addr):
        super(MTESan, self).to_shadow(addr)

    def shadow(self, addr, line_count):
        super(MTESan, self).shadow(addr, line_count)

    def whatis(self, addr):
        sme = self._sm.resolve(addr)
        mo = self._mo_provider.lookup(sme.addr)
        self._print_mo(mo, sme.addr)
        if mo.zone.z_btlog_kasan:
            print(
                " \nHistory of object (de)allocations is stored in btlog 0x{:x}."
                .format(mo.zone.z_btlog_kasan))

    def heap(self, addr):
        self.whatis(addr)

    def quarantine(self, qtype, addrs=None, n=None, show_bt=False, O=None):
        print("MTESan does not maintain a quarantine.")

    def legend(self):
        tags = [0x00, 0x80] + list(range(0xF0, 0xFF + 1))
        for tag in tags:
            print(" {:02x}: {:s}".format(tag, self.tag_name(tag)))

    @staticmethod
    def tag_name(tag):
        if tag == 0xFF:
            return "Allocated (default)"
        if 0xF1 <= tag <= 0xFE:
            return "Allocated"
        if tag == 0xF0:
            return "Freed"
        if tag == 0x80:
            return "Poisoned"
        if tag == 0x00:
            return "Cleared/Unmapped"
        return "Unknown"


def create_kasan():
    """ Creates a KASan instance for a KASan type detected in a kernel core.
        None if the core is not a KASan kernel variant.
    """
    if not hasattr(kern.globals, 'kasan_enabled'):
        return None
    if hasattr(kern.globals, 'kasan_tbi_enabled'):
        return MTESan.create()
    return ClassicKasan.create()


@lldb_command('kasan', 'C:T:S', fancy=True)
def Kasan(cmd_args=None, cmd_options=None, O=None):
    """Allows to inspect metadata KASan maintains for memory/stack objects.

    Usage:

        kasan <cmd> [opts..]

    Subcommands:

        Print general KASan runtime information

            kasan info

        Convert an address to a shadow map address

            kasan toshadow <addr>

        Convert a shadow map address to a respective memory object address

            kasan toaddr <shdw>

        Print a shadow map around provided address

            kasan shadow [-C <num>] <addr>

            -C <num>    Number of lines to print before and after the address

        Show metadata KASan maintains for a given address

            kasan whatis <addr>

        Show metadata of a heap object at a given address

            kasan heap <addr>

        Show quarantined addresses

            kasan quarantine [-T zalloc|kalloc|fakestack][-S][-C +-<num>][<addr1>...<addrN>]

            -T zalloc|kalloc|fakestack  Quarantine type
            -S                          Show backtraces
            -C +-<num>                  Show first/last <num> quarantined items
            <addr1>...<addrN>           List of addresses to look up in quarantine

            Address list and -C option are mutually exclusive.

        Show a shadow map tags legend

            kasan legend

    General Arguments:
    """

    kasan = create_kasan()
    if not kasan:
        print("KASan not enabled in build")
        return

    if not cmd_args:
        print(Kasan.__doc__)
        return

    # Since the VM is not aware of the KASan shadow mapping, accesses to it will
    # fail. Setting kdp_read_io=1 avoids this check.
    if GetConnectionProtocol() == "kdp" and unsigned(
            kern.globals.kdp_read_io) == 0:
        print("Setting kdp_read_io=1 to allow KASan shadow reads")
        if sizeof(kern.globals.kdp_read_io) == 4:
            WriteInt32ToMemoryAddress(1, addressof(kern.globals.kdp_read_io))
        elif sizeof(kern.globals.kdp_read_io) == 8:
            WriteInt64ToMemoryAddress(1, addressof(kern.globals.kdp_read_io))
        readio = unsigned(kern.globals.kdp_read_io)
        assert readio == 1

    kasan.command(cmd_args[0], cmd_args[1:], cmd_options, O)
