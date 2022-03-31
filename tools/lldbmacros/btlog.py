""" Some of the functionality here is a copy of existing macros from memory.py
    with the VM specific stuff removed so the macros work with any btlog.
    Eventually the zstack macros should be refactored to reuse the generic btlog
    support added here.
"""
from __future__ import absolute_import, division, print_function
from builtins import range
from builtins import object
import struct
from xnu import *

def _swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]

def _hash_ptr(ptr):
    h = unsigned(ptr)
    h >>= 4
    h *= 0x5052acdb
    h &= 0xffffffff
    return (h ^ _swap32(h)) & 0xffffffff

class BTStack(object):
    """
    Helper class to represent a backtrace in a library
    """

    REF_MASK       = 0x3fffffc0

    def __init__(self, btl, addr):
        self._btl = btl
        self._bts = kern.GetValueFromAddress(addr, 'bt_stack_t')

    def __len__(self):
        return int(self._bts.bts_ref_len) & 0xf

    def get_ref(self):
        return int(self._bts.bts_ref_len) >> 4

    def address(self):
        return int(self._bts)

    def hash(self):
        return int(self._bts.bts_hash)

    def next(self):
        # work around some weird cvalue.py bug
        v = cast(addressof(self._bts.bts_next), 'uint32_t *')
        return int(v[0])

    def smr_seq(self):
        return int(self._bts.bts_free_seq)

    def next_free(self):
        return int(self._bts.bts_free_next)

    def frames(self):
        base = unsigned(kern.GetGlobalVariable('vm_kernel_stext'))
        for i in range(0, len(self)):
            yield base + int(cast(self._bts.bts_frames[i], 'int'))

    def symbolicated_frames(self):
        for pc in self.frames():
            try:
                yield str(kern.SymbolicateFromAddress(pc, fullSymbol=True)[0])
            except:
                yield '{:<#x} ???>'.format(pc)

class BTLibrary(object):
    """
    Helper class to wrap backtrace libraries
    """

    PERMANENT      = 0x80000000
    SIZE_INIT      = 1 << 20
    BTL_HASH_COUNT = 256

    def __init__(self):
        self._btl = addressof(kern.GetGlobalVariable('bt_library'))

    def get_param(self):
        # work around some weird cvalue.py bug
        v = cast(addressof(self._btl.btl_param), 'uint32_t *')
        return int(v[0])

    def get_shift(self):
        return self.get_param() & 0x3f

    def get_parity(self):
        return self.get_param() >> 31

    def get_size(self):
        return 1 << int(32 - self.get_shift())

    def get_hash(self):
        return self._btl.btl_hash[self.get_parity()]

    def get_stack(self, ref):
        ref &= BTStack.REF_MASK
        if ref == 0:
            return BTStack(self, 0)

        for slab in range(0, 10):
            if ref < (BTLibrary.SIZE_INIT << slab):
                break

        return BTStack(self, int(self._btl.btl_slabs[slab] + ref))

class BTLog(object):
    """
    Helper class to abstract backtrace logs
    """

    OP_MASK = 0x3f
    END = 0xffffffff

    def __init__(self, addr):
        self._btl  = kern.GetValueFromAddress(addr, 'struct btlog *')
        self._cnt  = self._btl.btl_count
        self._btlh = None
        self._btll = None
        self._type = int(self._btl.btl_type)
        if self._type == GetEnumValue('btlog_type_t', 'BTLOG_LOG'):
            self._btll = kern.GetValueFromAddress(addr, 'struct btlog_log *')
        elif self._type == GetEnumValue('btlog_type_t', 'BTLOG_HASH'):
            self._btlh = kern.GetValueFromAddress(addr, 'struct btlog_hash *')
        self._index = None

    @header("{:<20s} {:<6s} {:>9s}".format("btlog", "type", "count"))
    def __str__(self):
        return "{:<#20x} {:<6s} {:>9d}".format(self._btl, self.get_type_str(), self._cnt)

    def is_log(self):
        return self._btll is not None

    def is_hash(self):
        return self._btlh is not None

    def _hash_mask(self):
        if self.is_hash():
            return (self._cnt >> 2) - 1

    def _hash_array(self):
        if self.is_hash():
            addr = int(addressof(self._btlh.btlh_entries[self._cnt]))
            return kern.GetValueFromAddress(addr, 'struct bt_hash_head *')

    def address(self):
        return int(self._btl)

    def get_type_str(self):
        return GetEnumName('btlog_type_t', self._type, 'BTLOG_')

    def index(self):
        if self._index is None:
            d = {}
            i = 0
            for _, _, op, ref in self.iter_records():
                i += 1
                if i % 1000 == 0:
                    sys.stderr.write("Indexing {:d}\r".format(i))

                k = (ref, op)
                if k in d:
                    d[k] += 1
                else:
                    d[k] = 1

            l = []
            for k in d.keys():
                l.append((k[0], k[1], d[k]))

            self._index = l

        return self._index

    def _decode(self, addr):
        addr = int(addr)
        if addr > 0xffffffff:
            addr ^= 0xffffffffffffffff
        else:
            addr ^= 0xffffffff
        return addr

    def _make_entry(self, idx, addr, where):
        addr = self._decode(addr)
        return (idx, addr, where & BTLog.OP_MASK, where & ~BTLog.OP_MASK)

    def _entry_matches(self, addr, where, wE, wB):
        if wE is not None and self._decode(addr) != wE:
            return False
        if wB is not None and (where & ~BTLog.OP_MASK) != wB:
            return False
        return True

    def iter_records(self, wantElement=None, wantBtref=None):
        if self.is_log():
            cnt = self._cnt
            pos = int(self._btll.btll_pos)
            if pos:
                for i in range(pos, cnt):
                    e = self._btll.btll_entries[i]
                    if e.btle_addr and self._entry_matches(e.btle_addr, e.btle_where, wantElement, wantBtref):
                        yield self._make_entry(i, e.btle_addr, e.btle_where)

            for i in range(0, pos):
                e = self._btll.btll_entries[i]
                if e.btle_addr and self._entry_matches(e.btle_addr, e.btle_where, wantElement, wantBtref):
                    yield self._make_entry(i, e.btle_addr, e.btle_where)

        elif self.is_hash():
            mask = self._hash_mask()
            arr  = self._hash_array()

            if wantElement is None:
                r = range(0, mask + 1)
            else:
                r = [_hash_ptr(int(wantElement)) & mask]

            for i in r:
                idx = int(arr[i].bthh_first)
                while idx != BTLog.END:
                    e   = self._btlh.btlh_entries[idx]
                    idx = int(e.bthe_next)
                    if self._entry_matches(e.bthe_addr, e.bthe_where, wantElement, wantBtref):
                        yield self._make_entry(idx, e.bthe_addr, e.bthe_where)

@lldb_command('showbtref', "A", fancy=True)
def ShowBTRef(cmd_args=None, cmd_options={}, O=None):
    """ Show a backtrace ref

        usage: showbtref [-A] <ref...>

            -A    arguments are raw addresses and not references
    """

    btl = BTLibrary()

    for arg in cmd_args:
        arg = int(kern.GetValueFromAddress(arg))
        if "-A" in cmd_options:
            bts = BTStack(btl, arg)
        else:
            bts = btl.get_stack(arg)
        print("Stack {:#x} {:#20x} (len: {:d}, ref: {:d}, hash:{:#10x}, next:{:#x})".format(
                arg, bts.address(), len(bts), bts.get_ref(), bts.hash(), bts.next()))

        for s in bts.symbolicated_frames():
            print(s)

@lldb_command('_showbtlibrary', fancy=True)
def ShowBTLibrary(cmd_args=None, cmd_options={}, O=None):
    """ Dump the entire bt library (debugging tool for the bt library itself)

        usage: showbtlibrary
    """
    btl = BTLibrary()
    bth = btl.get_hash()

    print("library {:#x}, buckets {:d}, stacks {:d}, parity {:d}, shift {:d}".format(
            btl._btl, btl.get_size(), btl._btl.btl_alloc_pos // 64,
            btl.get_parity(), btl.get_shift()))

    hdr = "{:<12s} {:<12s} {:<12s} {:>3s}  {:>5s}  {:<20s}".format("ref", "hash", "next", "len", "ref", "stack")
    hdr2 = hdr + "  {:<20s}".format("smr seq")

    with O.table("{:<20s} {:>6s} {:>6s}".format("hash", "idx", "slot")):
        for i in range(0, btl.get_size()):
            for j in range(0, BTLibrary.BTL_HASH_COUNT):
                ref = int(bth[i].bth_array[j].__smr_ptr)
                if ref == 0: continue

                print(O.format("{:<#20x} {:6d} {:6d}", bth[i], i, j))

                with O.table(hdr, indent=True):
                    while ref:
                        bts = btl.get_stack(ref)
                        err = ""
                        if (bts.hash() & 0xff) != j:
                            err = O.format(" {VT.DarkRed}wrong slot{VT.Default}")
                        if (bts.hash() >> btl.get_shift()) != i:
                            err += O.format(" {VT.DarkRed}wrong bucket{VT.Default}")

                        print(O.format("{:#010x}   {:#010x}   {:#010x}   {:>3d}  {:>5d}  {:<#20x}{:s}",
                            ref, bts.hash(), bts.next(), len(bts), bts.get_ref(), bts.address(), err))
                        ref = bts.next()

        print("freelist")
        ref = int(btl._btl.btl_free_head)
        with O.table(hdr2, indent=True):
            while ref:
                bts = btl.get_stack(ref)
                print(O.format("{:#010x}   {:#010x}   {:#010x}   {:>3d}  {:>5d}  {:<#20x}  {:<#20x}",
                    ref, bts.hash(), bts.next(), len(bts), bts.get_ref(), bts.address(), bts.smr_seq()))
                ref = bts.next_free()

@lldb_command('showbtlog', fancy=True)
def ShowBTLog(cmd_args=None, cmd_options={}, O=None):
    """ Display a summary of the specified btlog
        Usage: showbtlog <btlog address>
    """

    with O.table(BTLog.__str__.header):
        print(BTLog(cmd_args[0]))

@lldb_command('showbtlogrecords', 'B:E:F', fancy=True)
def ShowBTLogRecords(cmd_args=None, cmd_options={}, O=None):
    """ Print all records in the btlog from head to tail.

        Usage: showbtlogrecords <btlog addr> [-B <btref>] [-E <addr>] [-F]

            -B <btref>      limit output to elements with backtrace <ref>
            -E <addr>       limit output to elements with address <addr>
            -F              show full backtraces
    """

    if not cmd_args:
        return O.error('missing btlog argument')

    if "-B" in cmd_options:
        btref = int(kern.GetValueFromAddress(cmd_options["-B"]))
    else:
        btref = None

    if "-E" in cmd_options:
        element = kern.GetValueFromAddress(cmd_options["-E"])
    else:
        element = None

    btlib = BTLibrary()
    btlog = BTLog(cmd_args[0])

    with O.table("{:<10s}  {:<20s} {:>3s}  {:<10s}".format("idx", "element", "OP", "backtrace")):
        for idx, addr, op, ref in btlog.iter_records(wantElement=element, wantBtref=btref):
            print(O.format("{:<10d}  {:<#20x} {:>3d}  {:#010x}", idx, addr, op, ref))
            if "-F" in cmd_options:
                for s in btlib.get_stack(ref).symbolicated_frames():
                    print(O.format("    {:s}", s))
