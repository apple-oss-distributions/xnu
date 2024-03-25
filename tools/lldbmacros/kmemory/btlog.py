""" Some of the functionality here is a copy of existing macros from memory.py
    with the VM specific stuff removed so the macros work with any btlog.
    Eventually the zstack macros should be refactored to reuse the generic btlog
    support added here.
"""
import struct
import sys

from collections import namedtuple
from core import caching, xnu_format

# FIXME: should not import this from xnu
from xnu import GetSourceInformationForAddress

def _swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]

def _hash_ptr(ptr):
    h  = ptr >> 4
    h *= 0x5052acdb
    h &= 0xffffffff
    return (h ^ _swap32(h)) & 0xffffffff


class BTStack(object):
    """
    Helper class to represent a backtrace in a library
    """

    BTS_REF_MASK   = 0x3fffffc0
    BTS_FRAMES_MAX = 13

    def __init__(self, library, ref):
        ref &= BTStack.BTS_REF_MASK
        slab = 0

        while ref > (BTLibrary.SIZE_INIT << slab):
            slab += 1

        target   = library.target
        slab     = library.sbv.chkGetChildMemberWithName('btl_slabs').xGetIntegerAtIndex(slab)
        value    = target.xCreateValueFromAddress('stack', slab + ref, library.bts_type)
        target.xReadBytes(value.GetLoadAddress(), value.GetByteSize())

        self.sbv = value
        self.bts_ref = ref
        self.stext = library.stext

    def __len__(self):
        return self.sbv.xGetIntegerByName('bts_ref_len') & 0xf

    @property
    def bts_len(self):
        return len(self)

    @property
    def refcount(self):
        return self.sbv.xGetIntegerByName('bts_ref_len') >> 4

    @property
    def bts_hash(self):
        return self.sbv.xGetIntegerByName('bts_hash')

    @property
    def bts_next(self):
        return self.sbv.xGetIntegerByPath('.bts_next.__smr_ptr')

    @property
    def next_free(self):
        return self.sbv.xGetIntegerByName('bts_free_next')

    @property
    def frames(self):
        target = self.sbv.target
        addr   = self.sbv.xGetLoadAddressByName('bts_frames')
        stext  = self.stext
        return (stext + offs for offs in target.xIterAsInt32(addr, len(self)))

    def symbolicated_frames(self, prefix=" "):
        return (prefix + GetSourceInformationForAddress(pc) for pc in self.frames)

    def describe(self, verbose=False):
        fmt  = (
            "BTStack Info\n"
            " address              : {&v:#x}\n"
            " btref                : {0.bts_ref:#x}\n"
            " refcount             : {0.refcount}\n"
            " hash                 : {0.bts_hash:#010x}\n"
            " next                 : {0.bts_next:#x}\n"
            " backtrace"
        )
        print(xnu_format(fmt, self, v=self.sbv))

        print(*self.symbolicated_frames(prefix="  "), sep="\n")
        print()


class BTLibrary(object):
    """
    Helper class to wrap backtrace libraries
    """

    PERMANENT      = 0x80000000
    SIZE_INIT      = 1 << 20
    BTL_HASH_COUNT = 256
    BTL_SLABS      = 9

    def __init__(self, target):
        self.target = target

        #
        # Remember the types we will keep working with all the time
        #
        self.bts_type      = target.chkFindFirstType('union bt_stack')
        self.btl_type      = target.chkFindFirstType('struct btlog')
        self.btll_type     = target.chkFindFirstType('struct btlog_log')
        self.btlh_type     = target.chkFindFirstType('struct btlog_hash')
        self.bth_head_type = target.chkFindFirstType('struct bt_hash_head')

        self.sbv           = target.chkFindFirstGlobalVariable('bt_library')
        self.stext         = target.chkFindFirstGlobalVariable('vm_kernel_stext').xGetValueAsInteger()
        target.xReadBytes(self.sbv.GetLoadAddress(), self.sbv.GetByteSize())

    @staticmethod
    @caching.cache_statically
    def get_shared(target=None):
        """ Returns a shared instance of the class """

        return BTLibrary(target)

    def __len__(self):
        return self.sbv.xGetIntegerByName('btl_alloc_pos') // self.bts_type.GetByteSize()

    @property
    def size(self):
        return len(self)

    @property
    def param(self):
        return self.sbv.xGetIntegerByPath('.btl_param.__smr_ptr')

    @property
    def shift(self):
        return 32 - (self.param & 0x3f)

    @property
    def parity(self):
        return self.param >> 31

    @property
    def buckets(self):
        return 1 << self.shift

    @property
    def hash_address(self):
        path = ".btl_hash[{}]".format(self.parity)
        return self.sbv.xGetScalarByPath(path)

    @property
    def free_head(self):
        return self.sbv.xGetIntegerByName('btl_free_head')

    def btlog_from_address(self, address):
        return BTLog(self.sbv.xCreateValueFromAddress(
            'btlog', address, self.btl_type))

    def get_stack(self, ref):
        return BTStack(self, ref)

    def describe(self):
        fmt = (
            "BTLibrary Info\n"
            " buckets              : {0.buckets}\n"
            " stacks               : {0.size}\n"
            " parity               : {0.parity}\n"
            " shift                : {0.shift}\n"
            " hash address         : {0.hash_address:#x}\n"
        )
        print(xnu_format(fmt, self))


class BTLogEntry(namedtuple('BTLogEntry', ['index', 'address', 'op', 'ref'])):
    """ Represents a btlog entry """

    @classmethod
    def _make(cls, pos, value, key_addr, key_where):
        addr_mask = (1 << 8 * value.target.GetAddressByteSize()) - 1
        op_mask   = BTLog.OP_MASK
        addr      = value.xGetIntegerByName(key_addr)
        where     = value.xGetIntegerByName(key_where)
        if addr == 0:
            return cls(pos, 0, 0, 0)
        return cls(pos, addr ^ addr_mask, where & op_mask, where & ~op_mask)

    def matches(self, desiredAddress, desiredRef):
        if desiredAddress is not None and self.address != desiredAddress:
            return False
        if desiredRef is not None and self.ref != desiredRef:
            return False
        return self.address != 0


class BTLog(object):
    """
    Helper class to abstract backtrace logs
    """

    OP_MASK = 0x3f
    END     = 0xffffffff

    def __init__(self, orig_value):
        value = orig_value.chkDereference() if orig_value.TypeIsPointerType() else orig_value

        if value.GetType() != BTLibrary.get_shared().btl_type:
            raise TypeError("Argument is of unexpected type {}".format(
                orig_value.GetType().GetDisplayTypeName()))

        type_v = value.chkGetChildMemberWithName('btl_type')

        self._index = None
        self.sbv = value
        self.btl_type = next((
            e.GetName()[len('BTLOG_'):]
            for e in type_v.GetType().get_enum_members_array()
            if e.GetValueAsUnsigned() == type_v.GetValueAsUnsigned()
        ), "???")

    @property
    def address(self):
        return self.sbv.GetLoadAddress()

    @property
    def btl_count(self):
        return self.sbv.xGetIntegerByName('btl_count')

    def is_log(self):
        return self.btl_type == 'LOG'

    def is_hash(self):
        return self.btl_type == 'HASH'

    def index(self):
        if self._index is None:
            d = {}
            for i, (_, _, op, ref) in enumerate(self.iter_records()):
                if i % 1000 == 0:
                    sys.stderr.write("Indexing {:d}\r".format(i))

                d_ref = d.setdefault(ref, {})
                d_ref[op] = d_ref.get(op, 0) + 1

            self._index = list(
                (ref, op, v)
                for ref, d_ref in d.items()
                for op, v in d_ref.items()
            )

        return self._index

    def _iter_log_records(self, wantElement, wantBtref, reverse):
        target = self.sbv.target
        count  = self.btl_count

        btll   = self.sbv.chkCast(BTLibrary.get_shared().btll_type)
        pos    = btll.xGetIntegerByName('btll_pos')
        arr    = btll.chkGetValueForExpressionPath('.btll_entries[0]')

        base   = arr.GetLoadAddress()
        ty     = arr.GetType()
        tysz   = ty.GetByteSize()

        target.xReadBytes(arr.GetLoadAddress(), count * tysz)

        if reverse:
            indexes = (
                i if i < count else i - count
                for i in range(pos, pos + count).__reversed__()
            )
        else:
            indexes = (
                i if i < count else i - count
                for i in range(pos, pos + count)
            )

        entries = (
            BTLogEntry._make(
                idx,
                arr.chkCreateValueFromAddress('e', base + idx * tysz, ty),
                'btle_addr',
                'btle_where'
            )
            for idx in indexes
        )

        return (
            entry for entry in entries
            if entry.matches(wantElement, wantBtref)
        )

    def _iter_hash_records(self, wantElement, wantBtref, reverse):
        target  = self.sbv.target
        library = BTLibrary.get_shared()
        count   = self.btl_count

        btlh    = self.sbv.chkCast(library.btlh_type)
        e_arr   = btlh.chkGetValueForExpressionPath('.btlh_entries[0]')
        e_base  = e_arr.GetLoadAddress()

        e_ty    = e_arr.GetType()
        e_tysz  = e_ty.GetByteSize()
        h_ty    = library.bth_head_type
        h_tysz  = h_ty.GetByteSize()

        h_mask  = (count >> 2) - 1
        h_base  = e_base + count * e_tysz

        if wantElement is None:
            target.xReadBytes(e_arr.GetLoadAddress(), count * e_tysz + (count >> 2) * h_tysz)
            heads = (
                target.xCreateValueFromAddress(
                    None, h_base + i * h_tysz, h_ty).xGetIntegerByName('bthh_first')
                for i in range(h_mask + 1)
            )
        else:
            i = _hash_ptr(wantElement) & h_mask
            heads = (target.xCreateValueFromAddress(
                None, h_base + i * h_tysz, h_ty).xGetIntegerByName('bthh_first'), )

        for idx in heads:
            while idx != BTLog.END:
                elt   = e_arr.chkCreateValueFromAddress(None, e_base + idx * e_tysz, e_ty)
                entry = BTLogEntry._make(idx, elt, 'bthe_addr', 'bthe_where')
                if entry.matches(wantElement, wantBtref):
                    yield entry
                idx   = elt.xGetIntegerByName('bthe_next')

    def iter_records(self, wantElement=None, wantBtref=None, reverse=False):
        if self.is_log():
            return self._iter_log_records(wantElement, wantBtref, reverse)
        return self._iter_hash_records(wantElement, wantBtref, reverse)


__all__ = [
    BTLibrary.__name__,
    BTLog.__name__,
]
