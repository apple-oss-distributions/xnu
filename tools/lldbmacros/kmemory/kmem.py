"""
Wrappers around globals and caches to service the kmem package
"""
from abc import ABCMeta, abstractmethod
from collections import namedtuple
from core import (
    caching,
    gettype,
    lldbwrap,
)
from ctypes import c_int64

class MemoryRange(namedtuple('MemoryRange', ['start', 'end'])):
    @property
    def size(self):
        start, end = self
        return end - start

    def contains(self, addr):
        start, end = self
        return start <= addr < end

    def __repr__(self):
        return "{0.__class__.__name__}[{0.start:#x}, {0.end:#x})".format(self)


class VMPointerUnpacker(object):
    """
    Pointer unpacker for pointers packed with VM_PACK_POINTER()
    """
    def __init__(self, target, param_var):
        params = target.chkFindFirstGlobalVariable(param_var)
        self.base_relative = params.xGetScalarByName('vmpp_base_relative')
        self.bits          = params.xGetScalarByName('vmpp_bits')
        self.shift         = params.xGetScalarByName('vmpp_shift')
        self.base          = params.xGetScalarByName('vmpp_base')

    def unpack(self, packed):
        """
        Unpacks an address according to the VM_PACK_POINTER() scheme

        @param packed (int)
            The packed value to unpack

        @returns (int)
            The unpacked address
        """

        if not packed:
            return None

        if self.base_relative:
            addr = (packed << self.shift) + self.base
        else:
            bits  = self.bits
            shift = self.shift
            addr  = c_int64(packed << (64 - bits)).value
            addr >>= 64 - bits - shift

        return addr & 0xffffffffffffffff

    def unpack_value(self, sbv):
        """
        Conveniency wrapper for self.unpack(sbv.chkGetValueAsUnsigned())
        """
        return self.unpack(sbv.chkGetValueAsUnsigned())


class KMem(object, metaclass=ABCMeta):
    """
    Singleton class that holds various important information
    that is needed to make sense of the kernel memory layout,
    heap data structures, globals, ...
    """

    _HEAP_NAMES = [ "", "shared.", "data.", "" ]

    @staticmethod
    def _parse_range(zone_info_v, name):
        """
        Create a tuple representing a range (min_address, max_address, size)
        """
        range_v = zone_info_v.chkGetChildMemberWithName(name)
        left    = range_v.xGetIntegerByName('min_address')
        right   = range_v.xGetIntegerByName('max_address')
        return MemoryRange(left, right)

    def __init__(self, target):
        self.target = target

        #
        # Cache some globals everyone needs
        #
        self.page_shift = target.chkFindFirstGlobalVariable('page_shift').xGetValueAsInteger()
        self.page_size  = 1 << self.page_shift
        self.page_mask  = self.page_size - 1

        phase_v = target.chkFindFirstGlobalVariable('startup_phase')
        self.phase      = phase_v.xGetValueAsInteger()
        self.phases     = set(
            e.GetName()[len('STARTUP_SUB_'):]
            for e in phase_v.GetType().get_enum_members_array()
            if  e.GetValueAsUnsigned() <= self.phase
        )

        #
        # Setup the number of CPUs we have
        #
        self.ncpus      = target.chkFindFirstGlobalVariable('zpercpu_early_count').xGetValueAsInteger()
        self.master_cpu = target.chkFindFirstGlobalVariable('master_cpu').xGetValueAsInteger()
        self.zcpus      = range(self.ncpus) if 'ZALLOC' in self.phases else (self.master_cpu, )
        self.pcpus      = range(self.ncpus) if 'PERCPU' in self.phases else (self.master_cpu, )

        #
        # Load all the ranges we will need
        #
        zone_info = target.chkFindFirstGlobalVariable('zone_info')
        self.meta_range = self._parse_range(zone_info, 'zi_meta_range')
        self.bits_range = self._parse_range(zone_info, 'zi_bits_range')
        self.zone_range = self._parse_range(zone_info, 'zi_map_range')
        try:
            self.pgz_range = self._parse_range(zone_info, 'zi_pgz_range')
            self.pgz_bt    = target.chkFindFirstGlobalVariable('pgz_backtraces').xDereference()
        except:
            self.pgz_range = MemoryRange(0, 0)
            self.pgz_bt    = None

        kmem_ranges = target.chkFindFirstGlobalVariable('kmem_ranges')
        count       = kmem_ranges.GetByteSize() // target.GetAddressByteSize()
        addresses   = target.xIterAsUInt64(kmem_ranges.GetLoadAddress(), count)
        self.kmem_ranges = [
            MemoryRange(next(addresses), next(addresses))
            for i in range(0, count, 2)
        ]

        iokit_mach_vm_range = target.chkFindFirstGlobalVariable('gIOKitPageableFixedRange')
        self.iokit_range = MemoryRange(
            start=iokit_mach_vm_range.xGetIntegerByName('min_address'),
            end=iokit_mach_vm_range.xGetIntegerByName('max_address'),
        )

        #
        # And other important globals
        #
        self.stext      = target.chkFindFirstGlobalVariable('vm_kernel_stext').xGetValueAsInteger()
        self.num_zones  = target.chkFindFirstGlobalVariable('num_zones').xGetValueAsInteger()
        self.mag_size   = target.chkFindFirstGlobalVariable('_zc_mag_size').xGetValueAsInteger()
        self.zone_array = target.chkFindFirstGlobalVariable('zone_array')
        self.zsec_array = target.chkFindFirstGlobalVariable('zone_security_array')

        self.kernel_map = target.chkFindFirstGlobalVariable('kernel_map').Dereference()
        self.vm_kobject = target.chkFindFirstGlobalVariable('kernel_object_store')

        #
        # Cache some crucial types used for memory walks
        #
        self.zpm_type    = gettype('struct zone_page_metadata')
        self.vm_map_type = gettype('struct _vm_map')
        self.vmo_type    = self.vm_kobject.GetType()

        #
        # Recognize whether the target is any form of KASAN kernel.
        #
        if target.FindFirstGlobalVariable('kasan_enabled').IsValid():
            self.kasan         = True
            self.kasan_tbi     = target.FindFirstGlobalVariable('kasan_tbi_enabled').IsValid()
            self.kasan_classic = not self.kasan_tbi
        else:
            self.kasan         = False
            self.kasan_tbi     = False
            self.kasan_classic = False

        #
        # VM_PACK_POINTER Unpackers
        #
        self.kn_kq_packing = VMPointerUnpacker(target, 'kn_kq_packing_params')
        self.vm_page_packing = VMPointerUnpacker(target, 'vm_page_packing_params')
        try:
            self.rwlde_caller_packing = VMPointerUnpacker(target, 'rwlde_caller_packing_params')
        except ValueError:
            #
            # Release kernel doesn't define DEBUG_RW thus rwlde_caller_packing_params is compiled out
            #
            self.rwlde_caller_packing = None

        self.c_slot_packing = VMPointerUnpacker(target, 'c_slot_packing_params')

    @staticmethod
    @caching.cache_statically
    def get_shared(target=None):
        """
        Returns a shared instance of the class
        """

        arch = target.triple[:target.triple.find('-')]

        if arch.startswith('arm64e'):
            return _KMemARM64e(target)
        elif arch.startswith('arm64'):
            return _KMemARM64(target)
        elif arch.startswith('x86_64'):
            return _KMemX86(target)
        else:
            raise RuntimeError("Unsupported architecture: {}".format(arch))

    def iter_addresses(self, iterable):
        """
        Conveniency wrapper to transform a list of integer to addresses
        """
        return (self.make_address(a) for a in iterable)

    #
    # Abstract per-arch methods
    #

    @property
    @abstractmethod
    def has_ptrauth(self):
        """ whether this target has ptrauth """

        pass

    @abstractmethod
    def PERCPU_BASE(self, cpu):
        """
        Returns the per-cpu base for a given CPU number

        @param cpu (int)
            A CPU number

        @returns (int)
            The percpu base for this CPU
        """

        pass

    @abstractmethod
    def make_address(self, addr):
        """
        Make an address out of an integer

        @param addr (int)
            An address to convert

        @returns (int)
        """

        pass


class _KMemARM64(KMem):
    """
    Specialization of KMem for arm64
    """

    def __init__(self, target):
        super().__init__(target)

        self.arm64_CpuDataEntries = target.chkFindFirstGlobalVariable('CpuDataEntries')
        self.arm64_BootCpuData    = target.chkFindFirstGlobalVariable('percpu_slot_cpu_data')
        self.arm64_t1sz           = target.chkFindFirstGlobalVariable('gT1Sz').xGetValueAsInteger()
        self.arm64_sign_mask      = 1 << (63 - self.arm64_t1sz)

    @property
    def has_ptrauth(self):
        return False

    def PERCPU_BASE(self, cpu):
        cpu_data   = self.arm64_CpuDataEntries.chkGetChildAtIndex(cpu)
        boot_vaddr = self.arm64_BootCpuData.GetLoadAddress()

        return cpu_data.xGetIntegerByName('cpu_data_vaddr') - boot_vaddr

    def make_address(self, addr):
        sign_mask = self.arm64_sign_mask
        addr = addr & (sign_mask + sign_mask - 1)
        return ((addr ^ sign_mask) - sign_mask) & 0xffffffffffffffff


class _KMemARM64e(_KMemARM64):
    """
    Specialization of KMem for arm64e
    """

    @property
    def has_ptrauth(self):
        return True


class _KMemX86(KMem):
    """
    Specialization of KMem for Intel
    """

    def __init__(self, target):
        super().__init__(target)

        self.intel_cpu_data = target.chkFindFirstGlobalVariable('cpu_data_ptr')

    @property
    def has_ptrauth(self):
        return False

    def PERCPU_BASE(self, cpu):
        cpu_data = self.intel_cpu_data.chkGetChildAtIndex(cpu)
        return cpu_data.xGetIntegerByName('cpu_pcpu_base')

    def make_address(self, addr):
        return addr


class PERCPUValue(object):
    """
    Provides an enumerator for a percpu value
    """

    def __init__(self, name, target = None):
        """
        @param name (str)
            The percpu slot name

        @param target (SBTarget or None)
        """

        self.kmem = KMem.get_shared()
        self.sbv  = self.kmem.target.chkFindFirstGlobalVariable('percpu_slot_' + name)

    def __getitem__(self, cpu):
        if cpu in self.kmem.pcpus:
            sbv  = self.sbv
            addr = sbv.GetLoadAddress() + self.kmem.PERCPU_BASE(cpu)
            return sbv.chkCreateValueFromAddress(sbv.GetName(), addr, sbv.GetType())
        raise IndexError

    def __iter__(self):
        return (item[1] for items in self.items())

    def items(self):
        """
        Iterator of (cpu, SBValue) tuples for the given PERCPUValue
        """

        kmem = self.kmem
        sbv  = self.sbv
        name = sbv.GetName()
        ty   = sbv.GetType()
        addr = sbv.GetLoadAddress()

        return (
            (cpu, sbv.chkCreateValueFromAddress(name, addr + kmem.PERCPU_BASE(cpu), ty))
            for cpu in kmem.pcpus
        )

__all__ = [
    KMem.__name__,
    MemoryRange.__name__,
    PERCPUValue.__name__,
]
