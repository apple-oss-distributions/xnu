from xnu import *
import xnudefines
from kdp import *
from utils import *
import struct
from collections import namedtuple

def ReadPhysInt(phys_addr, bitsize = 64, cpuval = None):
    """ Read a physical memory data based on address.
        params:
            phys_addr : int - Physical address to read
            bitsize   : int - defines how many bytes to read. defaults to 64 bit
            cpuval    : None (optional)
        returns:
            int - int value read from memory. in case of failure 0xBAD10AD is returned.
    """
    if "kdp" == GetConnectionProtocol():
        return KDPReadPhysMEM(phys_addr, bitsize)

    # NO KDP. Attempt to use physical memory
    paddr_in_kva = kern.PhysToKernelVirt(int(phys_addr))
    if paddr_in_kva:
        if bitsize == 64 :
            return kern.GetValueFromAddress(paddr_in_kva, 'uint64_t *').GetSBValue().Dereference().GetValueAsUnsigned()
        if bitsize == 32 :
            return kern.GetValueFromAddress(paddr_in_kva, 'uint32_t *').GetSBValue().Dereference().GetValueAsUnsigned()
        if bitsize == 16 :
            return kern.GetValueFromAddress(paddr_in_kva, 'uint16_t *').GetSBValue().Dereference().GetValueAsUnsigned()
        if bitsize == 8 :
            return kern.GetValueFromAddress(paddr_in_kva, 'uint8_t *').GetSBValue().Dereference().GetValueAsUnsigned()
    return 0xBAD10AD

@lldb_command('readphys')
def ReadPhys(cmd_args = None):
    """ Reads the specified untranslated address
        The argument is interpreted as a physical address, and the 64-bit word
        addressed is displayed.
        usage: readphys <nbits> <address>
        nbits: 8,16,32,64
        address: 1234 or 0x1234 or `foo_ptr`
    """
    if cmd_args is None or len(cmd_args) < 2:
        raise ArgumentError()

    else:
        nbits = ArgumentStringToInt(cmd_args[0])
        phys_addr = ArgumentStringToInt(cmd_args[1])
        print("{0: <#x}".format(ReadPhysInt(phys_addr, nbits)))
    return True

lldb_alias('readphys8', 'readphys 8 ')
lldb_alias('readphys16', 'readphys 16 ')
lldb_alias('readphys32', 'readphys 32 ')
lldb_alias('readphys64', 'readphys 64 ')

def KDPReadPhysMEM(address, bits):
    """ Setup the state for READPHYSMEM64 commands for reading data via kdp
        params:
            address : int - address where to read the data from
            bits : int - number of bits in the intval (8/16/32/64)
        returns:
            int: read value from memory.
            0xBAD10AD: if failed to read data.
    """
    retval = 0xBAD10AD
    if "kdp" != GetConnectionProtocol():
        print("Target is not connected over kdp. Nothing to do here.")
        return retval

    if "hwprobe" == KDPMode():
        # Send the proper KDP command and payload to the bare metal debug tool via a KDP server
        addr_for_kdp = struct.unpack("<Q", struct.pack(">Q", address))[0]
        byte_count = struct.unpack("<I", struct.pack(">I", bits // 8))[0]
        packet = "{0:016x}{1:08x}{2:04x}".format(addr_for_kdp, byte_count, 0x0)

        ret_obj = lldb.SBCommandReturnObject()
        ci = lldb.debugger.GetCommandInterpreter()
        ci.HandleCommand('process plugin packet send -c 25 -p {0}'.format(packet), ret_obj)

        if ret_obj.Succeeded():
            value = ret_obj.GetOutput()

            if bits == 64 :
                pack_fmt = "<Q"
                unpack_fmt = ">Q"
            if bits == 32 :
                pack_fmt = "<I"
                unpack_fmt = ">I"
            if bits == 16 :
                pack_fmt = "<H"
                unpack_fmt = ">H"
            if bits == 8 :
                pack_fmt = "<B"
                unpack_fmt = ">B"

            retval = struct.unpack(unpack_fmt, struct.pack(pack_fmt, int(value[-((bits // 4)+1):], 16)))[0]

    else:
        input_address = unsigned(addressof(kern.globals.manual_pkt.input))
        len_address = unsigned(addressof(kern.globals.manual_pkt.len))
        data_address = unsigned(addressof(kern.globals.manual_pkt.data))

        if not WriteInt32ToMemoryAddress(0, input_address):
            return retval

        kdp_pkt_size = GetType('kdp_readphysmem64_req_t').GetByteSize()
        if not WriteInt32ToMemoryAddress(kdp_pkt_size, len_address):
            return retval

        data_addr = int(addressof(kern.globals.manual_pkt))
        pkt = kern.GetValueFromAddress(data_addr, 'kdp_readphysmem64_req_t *')

        header_value =GetKDPPacketHeaderInt(request=GetEnumValue('kdp_req_t::KDP_READPHYSMEM64'), length=kdp_pkt_size)

        if ( WriteInt64ToMemoryAddress((header_value), int(addressof(pkt.hdr))) and
             WriteInt64ToMemoryAddress(address, int(addressof(pkt.address))) and
             WriteInt32ToMemoryAddress((bits // 8), int(addressof(pkt.nbytes))) and
             WriteInt16ToMemoryAddress(xnudefines.lcpu_self, int(addressof(pkt.lcpu)))
             ):

            if WriteInt32ToMemoryAddress(1, input_address):
                # now read data from the kdp packet
                data_address = unsigned(addressof(kern.GetValueFromAddress(int(addressof(kern.globals.manual_pkt.data)), 'kdp_readphysmem64_reply_t *').data))
                if bits == 64 :
                    retval =  kern.GetValueFromAddress(data_address, 'uint64_t *').GetSBValue().Dereference().GetValueAsUnsigned()
                if bits == 32 :
                    retval =  kern.GetValueFromAddress(data_address, 'uint32_t *').GetSBValue().Dereference().GetValueAsUnsigned()
                if bits == 16 :
                    retval =  kern.GetValueFromAddress(data_address, 'uint16_t *').GetSBValue().Dereference().GetValueAsUnsigned()
                if bits == 8 :
                    retval =  kern.GetValueFromAddress(data_address, 'uint8_t *').GetSBValue().Dereference().GetValueAsUnsigned()

    return retval


def KDPWritePhysMEM(address, intval, bits):
    """ Setup the state for WRITEPHYSMEM64 commands for saving data in kdp
        params:
            address : int - address where to save the data
            intval : int - integer value to be stored in memory
            bits : int - number of bits in the intval (8/16/32/64)
        returns:
            boolean: True if the write succeeded.
    """
    if "kdp" != GetConnectionProtocol():
        print("Target is not connected over kdp. Nothing to do here.")
        return False
    
    if "hwprobe" == KDPMode():
        # Send the proper KDP command and payload to the bare metal debug tool via a KDP server
        addr_for_kdp = struct.unpack("<Q", struct.pack(">Q", address))[0]
        byte_count = struct.unpack("<I", struct.pack(">I", bits // 8))[0]

        if bits == 64 :
            pack_fmt = ">Q"
            unpack_fmt = "<Q"
        if bits == 32 :
            pack_fmt = ">I"
            unpack_fmt = "<I"
        if bits == 16 :
            pack_fmt = ">H"
            unpack_fmt = "<H"
        if bits == 8 :
            pack_fmt = ">B"
            unpack_fmt = "<B"

        data_val = struct.unpack(unpack_fmt, struct.pack(pack_fmt, intval))[0]

        packet = "{0:016x}{1:08x}{2:04x}{3:016x}".format(addr_for_kdp, byte_count, 0x0, data_val)

        ret_obj = lldb.SBCommandReturnObject()
        ci = lldb.debugger.GetCommandInterpreter()
        ci.HandleCommand('process plugin packet send -c 26 -p {0}'.format(packet), ret_obj)

        if ret_obj.Succeeded():
            return True
        else:
            return False

    else:
        input_address = unsigned(addressof(kern.globals.manual_pkt.input))
        len_address = unsigned(addressof(kern.globals.manual_pkt.len))
        data_address = unsigned(addressof(kern.globals.manual_pkt.data))
        if not WriteInt32ToMemoryAddress(0, input_address):
            return False

        kdp_pkt_size = GetType('kdp_writephysmem64_req_t').GetByteSize() + (bits // 8)
        if not WriteInt32ToMemoryAddress(kdp_pkt_size, len_address):
            return False

        data_addr = int(addressof(kern.globals.manual_pkt))
        pkt = kern.GetValueFromAddress(data_addr, 'kdp_writephysmem64_req_t *')

        header_value =GetKDPPacketHeaderInt(request=GetEnumValue('kdp_req_t::KDP_WRITEPHYSMEM64'), length=kdp_pkt_size)

        if ( WriteInt64ToMemoryAddress((header_value), int(addressof(pkt.hdr))) and
             WriteInt64ToMemoryAddress(address, int(addressof(pkt.address))) and
             WriteInt32ToMemoryAddress(bits // 8, int(addressof(pkt.nbytes))) and
             WriteInt16ToMemoryAddress(xnudefines.lcpu_self, int(addressof(pkt.lcpu)))
             ):

            if bits == 8:
                if not WriteInt8ToMemoryAddress(intval, int(addressof(pkt.data))):
                    return False
            if bits == 16:
                if not WriteInt16ToMemoryAddress(intval, int(addressof(pkt.data))):
                    return False
            if bits == 32:
                if not WriteInt32ToMemoryAddress(intval, int(addressof(pkt.data))):
                    return False
            if bits == 64:
                if not WriteInt64ToMemoryAddress(intval, int(addressof(pkt.data))):
                    return False
            if WriteInt32ToMemoryAddress(1, input_address):
                return True
        return False


def WritePhysInt(phys_addr, int_val, bitsize = 64):
    """ Write and integer value in a physical memory data based on address.
        params:
            phys_addr : int - Physical address to read
            int_val   : int - int value to write in memory
            bitsize   : int - defines how many bytes to read. defaults to 64 bit
        returns:
            bool - True if write was successful.
    """
    if "kdp" == GetConnectionProtocol():
        if not KDPWritePhysMEM(phys_addr, int_val, bitsize):
            print("Failed to write via KDP.")
            return False
        return True
    #We are not connected via KDP. So do manual math and savings.
    print("Failed: Write to physical memory is not supported for %s connection." % GetConnectionProtocol())
    return False

@lldb_command('writephys')
def WritePhys(cmd_args=None):
    """ writes to the specified untranslated address
        The argument is interpreted as a physical address, and the 64-bit word
        addressed is displayed.
        usage: writephys <nbits> <address> <value>
        nbits: 8,16,32,64
        address: 1234 or 0x1234 or `foo_ptr`
        value: int value to be written
        ex. (lldb)writephys 16 0x12345abcd 0x25
    """
    if cmd_args is None or len(cmd_args) < 3:
        raise ArgumentError()

    else:
        nbits = ArgumentStringToInt(cmd_args[0])
        phys_addr = ArgumentStringToInt(cmd_args[1])
        int_value = ArgumentStringToInt(cmd_args[2])
        print(WritePhysInt(phys_addr, int_value, nbits))


lldb_alias('writephys8', 'writephys 8 ')
lldb_alias('writephys16', 'writephys 16 ')
lldb_alias('writephys32', 'writephys 32 ')
lldb_alias('writephys64', 'writephys 64 ')


def _PT_Step(paddr, index, verbose_level = vSCRIPT):
    """
     Step to lower-level page table and print attributes
       paddr: current page table entry physical address
       index: current page table entry index (0..511)
       verbose_level:    vHUMAN: print nothing
                         vSCRIPT: print basic information
                         vDETAIL: print basic information and hex table dump
     returns: (pt_paddr, pt_valid, pt_large)
       pt_paddr: next level page table entry physical address
                      or null if invalid
       pt_valid: 1 if $kgm_pt_paddr is valid, 0 if the walk
                      should be aborted
       pt_large: 1 if kgm_pt_paddr is a page frame address
                      of a large page and not another page table entry
    """
    entry_addr = paddr + (8 * index)
    entry = ReadPhysInt(entry_addr, 64, xnudefines.lcpu_self )
    out_string = ''
    if verbose_level >= vDETAIL:
        for pte_loop in range(0, 512):
            paddr_tmp = paddr + (8 * pte_loop)
            out_string += "{0: <#020x}:\t {1: <#020x}\n".format(paddr_tmp, ReadPhysInt(paddr_tmp, 64, xnudefines.lcpu_self))
    paddr_mask = ~((0xfff<<52) | 0xfff)
    paddr_large_mask =  ~((0xfff<<52) | 0x1fffff)
    pt_valid = False
    pt_large = False
    pt_paddr = 0
    if verbose_level < vSCRIPT:
        if entry & 0x1 :
            pt_valid = True
            pt_large = False
            pt_paddr = entry & paddr_mask
            if entry & (0x1 <<7):
                pt_large = True
                pt_paddr = entry & paddr_large_mask
    else:
        out_string+= "{0: <#020x}:\n\t{1:#020x}\n\t".format(entry_addr, entry)
        if entry & 0x1:
            out_string += " valid"
            pt_paddr = entry & paddr_mask
            pt_valid = True
        else:
            out_string += " invalid"
            pt_paddr = 0
            pt_valid = False
            if entry & (0x1 << 62):
                out_string += " compressed"
            #Stop decoding other bits
            entry = 0
        if entry & (0x1 << 1):
            out_string += " writable"
        else:
            out_string += " read-only"

        if entry & (0x1 << 2):
            out_string += " user"
        else:
            out_string += " supervisor"

        if entry & (0x1 << 3):
            out_string += " PWT"

        if entry & (0x1 << 4):
            out_string += " PCD"

        if entry & (0x1 << 5):
            out_string += " accessed"

        if entry & (0x1 << 6):
            out_string += " dirty"

        if entry & (0x1 << 7):
            out_string += " large"
            pt_large = True
        else:
            pt_large = False

        if entry & (0x1 << 8):
            out_string += " global"

        if entry & (0x3 << 9):
            out_string += " avail:{0:x}".format((entry >> 9) & 0x3)

        if entry & (0x1 << 63):
            out_string += " noexec"
    print(out_string)
    return (pt_paddr, pt_valid, pt_large)

def _PT_StepEPT(paddr, index, verbose_level = vSCRIPT):
    """
     Step to lower-level page table and print attributes for EPT pmap
       paddr: current page table entry physical address
       index: current page table entry index (0..511)
       verbose_level:    vHUMAN: print nothing
                         vSCRIPT: print basic information
                         vDETAIL: print basic information and hex table dump
     returns: (pt_paddr, pt_valid, pt_large)
       pt_paddr: next level page table entry physical address
                      or null if invalid
       pt_valid: 1 if $kgm_pt_paddr is valid, 0 if the walk
                      should be aborted
       pt_large: 1 if kgm_pt_paddr is a page frame address
                      of a large page and not another page table entry
    """
    entry_addr = paddr + (8 * index)
    entry = ReadPhysInt(entry_addr, 64, xnudefines.lcpu_self )
    out_string = ''
    if verbose_level >= vDETAIL:
        for pte_loop in range(0, 512):
            paddr_tmp = paddr + (8 * pte_loop)
            out_string += "{0: <#020x}:\t {1: <#020x}\n".format(paddr_tmp, ReadPhysInt(paddr_tmp, 64, xnudefines.lcpu_self))
    paddr_mask = ~((0xfff<<52) | 0xfff)
    paddr_large_mask =  ~((0xfff<<52) | 0x1fffff)
    pt_valid = False
    pt_large = False
    pt_paddr = 0
    if verbose_level < vSCRIPT:
        if entry & 0x7 :
            pt_valid = True
            pt_large = False
            pt_paddr = entry & paddr_mask
            if entry & (0x1 <<7):
                pt_large = True
                pt_paddr = entry & paddr_large_mask
    else:
        out_string+= "{0: <#020x}:\n\t{1:#020x}\n\t".format(entry_addr, entry)
        if entry & 0x7:
            out_string += "valid"
            pt_paddr = entry & paddr_mask
            pt_valid = True
        else:
            out_string += "invalid"
            pt_paddr = 0
            pt_valid = False
            if entry & (0x1 << 62):
                out_string += " compressed"
            #Stop decoding other bits
            entry = 0
        if entry & 0x1:
            out_string += " readable"
        else:
            out_string += " no read"
        if entry & (0x1 << 1):
            out_string += " writable"
        else:
            out_string += " no write"

        if entry & (0x1 << 2):
            out_string += " executable"
        else:
            out_string += " no exec"

        ctype = entry & 0x38
        if ctype == 0x30:
            out_string += " cache-WB"
        elif ctype == 0x28:
            out_string += " cache-WP"
        elif ctype == 0x20:
            out_string += " cache-WT"
        elif ctype == 0x8:
            out_string += " cache-WC"
        else:
            out_string += " cache-NC"

        if (entry & 0x40) == 0x40:
            out_string += " Ignore-PTA"

        if (entry & 0x100) == 0x100:
            out_string += " accessed"

        if (entry & 0x200) == 0x200:
            out_string += " dirty"

        if entry & (0x1 << 7):
            out_string += " large"
            pt_large = True
        else:
            pt_large = False
    print(out_string)
    return (pt_paddr, pt_valid, pt_large)

def _PmapL4Walk(pmap_addr_val,vaddr, ept_pmap, verbose_level = vSCRIPT):
    """ Walk the l4 pmap entry.
        params: pmap_addr_val - core.value representing kernel data of type pmap_addr_t
        vaddr : int - virtual address to walk
    """
    pt_paddr = unsigned(pmap_addr_val)
    pt_valid = (unsigned(pmap_addr_val) != 0)
    pt_large = 0
    pframe_offset = 0
    if pt_valid:
        # Lookup bits 47:39 of linear address in PML4T
        pt_index = (vaddr >> 39) & 0x1ff
        pframe_offset = vaddr & 0x7fffffffff
        if verbose_level > vHUMAN :
            print("pml4 (index {0:d}):".format(pt_index))
        if not(ept_pmap):
            (pt_paddr, pt_valid, pt_large) = _PT_Step(pt_paddr, pt_index, verbose_level)
        else:
            (pt_paddr, pt_valid, pt_large) = _PT_StepEPT(pt_paddr, pt_index, verbose_level)
    if pt_valid:
        # Lookup bits 38:30 of the linear address in PDPT
        pt_index = (vaddr >> 30) & 0x1ff
        pframe_offset = vaddr & 0x3fffffff
        if verbose_level > vHUMAN:
            print("pdpt (index {0:d}):".format(pt_index))
        if not(ept_pmap):
            (pt_paddr, pt_valid, pt_large) = _PT_Step(pt_paddr, pt_index, verbose_level)
        else:
            (pt_paddr, pt_valid, pt_large) = _PT_StepEPT(pt_paddr, pt_index, verbose_level)
    if pt_valid and not pt_large:
        #Lookup bits 29:21 of the linear address in PDPT
        pt_index = (vaddr >> 21) & 0x1ff
        pframe_offset = vaddr & 0x1fffff
        if verbose_level > vHUMAN:
            print("pdt (index {0:d}):".format(pt_index))
        if not(ept_pmap):
            (pt_paddr, pt_valid, pt_large) = _PT_Step(pt_paddr, pt_index, verbose_level)
        else:
            (pt_paddr, pt_valid, pt_large) = _PT_StepEPT(pt_paddr, pt_index, verbose_level)
    if pt_valid and not pt_large:
        #Lookup bits 20:21 of linear address in PT
        pt_index = (vaddr >> 12) & 0x1ff
        pframe_offset = vaddr & 0xfff
        if verbose_level > vHUMAN:
            print("pt (index {0:d}):".format(pt_index))
        if not(ept_pmap):
            (pt_paddr, pt_valid, pt_large) = _PT_Step(pt_paddr, pt_index, verbose_level)
        else:
            (pt_paddr, pt_valid, pt_large) = _PT_StepEPT(pt_paddr, pt_index, verbose_level)
    paddr = 0
    paddr_isvalid = False
    if pt_valid:
        paddr = pt_paddr + pframe_offset
        paddr_isvalid = True

    if verbose_level > vHUMAN:
        if paddr_isvalid:
            pvalue = ReadPhysInt(paddr, 32, xnudefines.lcpu_self)
            print("phys {0: <#020x}: {1: <#020x}".format(paddr, pvalue))
        else:
            print("no translation")

    return paddr

def PmapWalkX86_64(pmapval, vaddr, verbose_level = vSCRIPT):
    """
        params: pmapval - core.value representing pmap_t in kernel
        vaddr:  int     - int representing virtual address to walk
    """
    if pmapval.pm_cr3 != 0:
        if verbose_level > vHUMAN:
            print("Using normal Intel PMAP from pm_cr3\n")
        return _PmapL4Walk(pmapval.pm_cr3, vaddr, 0, config['verbosity'])
    else:
        if verbose_level > vHUMAN:
            print("Using EPT pmap from pm_eptp\n")
        return _PmapL4Walk(pmapval.pm_eptp, vaddr, 1, config['verbosity'])

def assert_64bit(val):
    assert(val < 2**64)

ARM64_TTE_SIZE = 8
ARM64_TTE_SHIFT = 3
ARM64_VMADDR_BITS = 48

def PmapBlockOffsetMaskARM64(page_size, level):
    assert level >= 0 and level <= 3
    ttentries = (page_size // ARM64_TTE_SIZE)
    return page_size * (ttentries ** (3 - level)) - 1

def PmapBlockBaseMaskARM64(page_size, level):
    assert level >= 0 and level <= 3
    return ((1 << ARM64_VMADDR_BITS) - 1) & ~PmapBlockOffsetMaskARM64(page_size, level)

PmapTTEARM64 = namedtuple('PmapTTEARM64', ['level', 'value', 'stage2'])

def PmapDecodeTTEARM64(tte, level, stage2 = False, is_iommu_tte = False):
    """ Display the bits of an ARM64 translation table or page table entry
        in human-readable form.
        tte: integer value of the TTE/PTE
        level: translation table level.  Valid values are 1, 2, or 3.
        is_iommu_tte: True if the TTE is from an IOMMU's page table, False otherwise.
    """
    assert(isinstance(level, numbers.Integral))
    assert_64bit(tte)

    if tte & 0x1 == 0x0:
        print("Invalid.")
        return

    if (tte & 0x2 == 0x2) and (level != 0x3):
        print("Type       = Table pointer.")
        print("Table addr = {:#x}.".format(tte & 0xfffffffff000))

        if not stage2:
            print("PXN        = {:#x}.".format((tte >> 59) & 0x1))
            print("XN         = {:#x}.".format((tte >> 60) & 0x1))
            print("AP         = {:#x}.".format((tte >> 61) & 0x3))
            print("NS         = {:#x}.".format(tte >> 63))
    else:
        print("Type       = Block.")

        if stage2:
            print("S2 MemAttr = {:#x}.".format((tte >> 2) & 0xf))
        else:
            attr_index = (tte >> 2) & 0x7
            attr_string = { 0: 'WRITEBACK', 1: 'WRITECOMB', 2: 'WRITETHRU',
                3: 'CACHE DISABLE',
                4: 'RESERVED'
                ,
                5: 'POSTED (DISABLE_XS if FEAT_XS supported)',
                6: 'POSTED_REORDERED (POSTED_COMBINED_REORDERED if FEAT_XS supported)',
                7: 'POSTED_COMBINED_REORDERED (POSTED_COMBINED_REORDERED_XS if FEAT_XS supported)' }

            # Only show the string version of the AttrIdx for CPU mappings since
            # these values don't apply to IOMMU mappings.
            if is_iommu_tte:
                print("AttrIdx    = {:#x}.".format(attr_index))
            else:
                print("AttrIdx    = {:#x} ({:s}).".format(attr_index, attr_string[attr_index]))
            print("NS         = {:#x}.".format((tte >> 5) & 0x1))

        if stage2:
            print("S2AP       = {:#x}.".format((tte >> 6) & 0x3))
        else:
            print("AP         = {:#x}.".format((tte >> 6) & 0x3))

        print("SH         = {:#x}.".format((tte >> 8) & 0x3))
        print("AF         = {:#x}.".format((tte >> 10) & 0x1))

        if not stage2:
            print("nG         = {:#x}.".format((tte >> 11) & 0x1))

        print("HINT       = {:#x}.".format((tte >> 52) & 0x1))

        if stage2:
            print("S2XN       = {:#x}.".format((tte >> 53) & 0x3))
        else:
            print("PXN        = {:#x}.".format((tte >> 53) & 0x1))
            print("XN         = {:#x}.".format((tte >> 54) & 0x1))

        print("SW Use     = {:#x}.".format((tte >> 55) & 0xf))

    return

def PmapTTnIndexARM64(vaddr, pmap_pt_attr):
    pta_max_level = unsigned(pmap_pt_attr.pta_max_level)

    tt_index = []
    for i in range(pta_max_level + 1):
        tt_index.append((vaddr & unsigned(pmap_pt_attr.pta_level_info[i].index_mask)) \
            >> unsigned(pmap_pt_attr.pta_level_info[i].shift))

    return tt_index

def PmapWalkARM64(pmap_pt_attr, root_tte, vaddr, verbose_level = vHUMAN, extra=None):
    assert(type(vaddr) in (int, int))
    assert_64bit(vaddr)
    assert_64bit(root_tte)

    # Obtain pmap attributes
    page_size = pmap_pt_attr.pta_page_size
    page_offset_mask = (page_size - 1)
    page_base_mask = ((1 << ARM64_VMADDR_BITS) - 1) & (~page_offset_mask)
    tt_index = PmapTTnIndexARM64(vaddr, pmap_pt_attr)
    stage2 = bool(pmap_pt_attr.stage2 if hasattr(pmap_pt_attr, 'stage2') else False)

    # The pmap starts at a page table level that is defined by register
    # values; the root level can be obtained from the attributes structure
    level = unsigned(pmap_pt_attr.pta_root_level)

    root_tt_index = tt_index[level]
    root_pgtable_num_ttes = (unsigned(pmap_pt_attr.pta_level_info[level].index_mask) >> \
        unsigned(pmap_pt_attr.pta_level_info[level].shift)) + 1
    tte = int(unsigned(root_tte[root_tt_index]))

    # Walk the page tables
    paddr = None
    max_level = unsigned(pmap_pt_attr.pta_max_level)
    is_valid = True
    is_leaf = False

    if extra is not None:
        extra['page_size'] = page_size
        extra['page_mask'] = page_size - 1
        extra['paddr']     = None
        extra['is_valid']  = True
        extra['is_leaf']   = False
        extra['tte']       = []

    while (level <= max_level):
        if extra is not None:
            extra['tte'].append(PmapTTEARM64(level=level, value=tte, stage2=stage2))

        if verbose_level >= vSCRIPT:
            print("L{} entry: {:#x}".format(level, tte))
        if verbose_level >= vDETAIL:
            PmapDecodeTTEARM64(tte, level, stage2)

        if tte & 0x1 == 0x0:
            if verbose_level >= vHUMAN:
                print("L{} entry invalid: {:#x}\n".format(level, tte))

            if extra is not None:
                extra['is_valid'] = False
            is_valid = False
            break

        # Handle leaf entry
        if tte & 0x2 == 0x0 or level == max_level:
            base_mask = page_base_mask if level == max_level else PmapBlockBaseMaskARM64(page_size, level)
            offset_mask = page_offset_mask if level == max_level else PmapBlockOffsetMaskARM64(page_size, level)
            paddr = tte & base_mask
            paddr = paddr | (vaddr & offset_mask)

            if level != max_level:
                print("phys: {:#x}".format(paddr))

            if extra is not None:
                extra['is_leaf'] = True
                extra['paddr'] = paddr
            is_leaf = True
            break
        else:
        # Handle page table entry
            next_phys = (tte & page_base_mask) + (ARM64_TTE_SIZE * tt_index[level + 1])
            assert(isinstance(next_phys, numbers.Integral))

            next_virt = kern.PhysToKernelVirt(next_phys)
            assert(isinstance(next_virt, numbers.Integral))

            if verbose_level >= vDETAIL:
                print("L{} physical address: {:#x}. L{} virtual address: {:#x}".format(level + 1, next_phys, level + 1, next_virt))

            ttep = kern.GetValueFromAddress(next_virt, "tt_entry_t*")
            tte = int(unsigned(dereference(ttep)))
            assert(isinstance(tte, numbers.Integral))

        # We've parsed one level, so go to the next level
        assert(level <= 3)
        level = level + 1


    if verbose_level >= vHUMAN:
        if paddr:
            print("Translation of {:#x} is {:#x}.".format(vaddr, paddr))
        else:
            print("(no translation)")

    return paddr

def PmapWalk(pmap, vaddr, verbose_level = vHUMAN):
    if kern.arch == 'x86_64':
        return PmapWalkX86_64(pmap, vaddr, verbose_level)
    elif kern.arch.startswith('arm64'):
        # Obtain pmap attributes from pmap structure
        pmap_pt_attr = pmap.pmap_pt_attr if hasattr(pmap, 'pmap_pt_attr') else kern.globals.native_pt_attr
        return PmapWalkARM64(pmap_pt_attr, pmap.tte, vaddr, verbose_level)
    else:
        raise NotImplementedError("PmapWalk does not support {0}".format(kern.arch))

@lldb_command('pmap_walk')
def PmapWalkHelper(cmd_args=None):
    """ Perform a page-table walk in <pmap> for <virtual_address>.
        Syntax: (lldb) pmap_walk <pmap> <virtual_address> [-v] [-e]
            Multiple -v's can be specified for increased verbosity
    """
    if cmd_args is None or len(cmd_args) < 2:
        raise ArgumentError("Too few arguments to pmap_walk.")

    pmap = kern.GetValueAsType(cmd_args[0], 'pmap_t')
    addr = ArgumentStringToInt(cmd_args[1])
    PmapWalk(pmap, addr, config['verbosity'])
    return

def GetMemoryAttributesFromUser(requested_type):
    pmap_attr_dict = {
        '4k' : kern.globals.pmap_pt_attr_4k,
        '16k' : kern.globals.pmap_pt_attr_16k,
        '16k_s2' : kern.globals.pmap_pt_attr_16k_stage2 if hasattr(kern.globals, 'pmap_pt_attr_16k_stage2') else None,
    }

    requested_type = requested_type.lower()
    if requested_type not in pmap_attr_dict:
        return None

    return pmap_attr_dict[requested_type]

@lldb_command('ttep_walk')
def TTEPWalkPHelper(cmd_args=None):
    """ Perform a page-table walk in <root_ttep> for <virtual_address>.
        Syntax: (lldb) ttep_walk <root_ttep> <virtual_address> [4k|16k|16k_s2] [-v] [-e]
        Multiple -v's can be specified for increased verbosity
        """
    if cmd_args is None or len(cmd_args) < 2:
        raise ArgumentError("Too few arguments to ttep_walk.")

    if not kern.arch.startswith('arm64'):
        raise NotImplementedError("ttep_walk does not support {0}".format(kern.arch))

    tte = kern.GetValueFromAddress(kern.PhysToKernelVirt(ArgumentStringToInt(cmd_args[0])), 'unsigned long *')
    addr = ArgumentStringToInt(cmd_args[1])

    pmap_pt_attr = kern.globals.native_pt_attr if len(cmd_args) < 3 else GetMemoryAttributesFromUser(cmd_args[2])
    if pmap_pt_attr is None:
        raise ArgumentError("Invalid translation attribute type.")

    return PmapWalkARM64(pmap_pt_attr, tte, addr, config['verbosity'])

@lldb_command('decode_tte')
def DecodeTTE(cmd_args=None):
    """ Decode the bits in the TTE/PTE value specified <tte_val> for translation level <level> and stage [s1|s2]
        Syntax: (lldb) decode_tte <tte_val> <level> [s1|s2]
    """
    if cmd_args is None or len(cmd_args) < 2:
        raise ArgumentError("Too few arguments to decode_tte.")
    if len(cmd_args) > 2 and cmd_args[2] not in ["s1", "s2"]:
        raise ArgumentError("{} is not a valid stage of translation.".format(cmd_args[2]))
    if kern.arch.startswith('arm64'):
        stage2 = True if len(cmd_args) > 2 and cmd_args[2] == "s2" else False
        PmapDecodeTTEARM64(ArgumentStringToInt(cmd_args[0]), ArgumentStringToInt(cmd_args[1]), stage2)
    else:
        raise NotImplementedError("decode_tte does not support {0}".format(kern.arch))

PVH_HIGH_FLAGS_ARM64 = (1 << 62) | (1 << 61) | (1 << 60) | (1 << 59) | (1 << 58) | (1 << 57) | (1 << 56) | (1 << 55) | (1 << 54)
PVH_HIGH_FLAGS_ARM32 = (1 << 31)

def PVDumpPTE(pvep, ptep, verbose_level = vHUMAN):
    """ Dump information about a single mapping retrieved by the pv_head_table.

        pvep: Either a pointer to the PVE object if the PVH entry is PVH_TYPE_PVEP,
              or None if type PVH_TYPE_PTEP.
        ptep: For type PVH_TYPE_PTEP this should just be the raw PVH entry with
              the high flags already set (the type bits don't need to be cleared).
              For type PVH_TYPE_PVEP this will be the value retrieved from the
              pve_ptep[] array.
    """
    if kern.arch.startswith('arm64'):
        iommu_flag = 0x4
        iommu_table_flag = 1 << 63
    else:
        iommu_flag = 0
        iommu_table_flag = 0

    # AltAcct status is only stored in the ptep for PVH_TYPE_PVEP entries.
    if pvep is not None and (ptep & 0x1):
        # Note: It's not possible for IOMMU mappings to be marked as alt acct so
        # setting this string is mutually exclusive with setting the IOMMU strings.
        pte_str = ' (alt acct)'
    else:
        pte_str = ''

    if pvep is not None:
        pve_str = 'PVEP {:#x}, '.format(pvep)
    else:
        pve_str = ''

    # For PVH_TYPE_PTEP, this clears out the type bits. For PVH_TYPE_PVEP, this
    # either does nothing or clears out the AltAcct bit.
    ptep = ptep & ~0x3

    # When printing with extra verbosity, print an extra newline that describes
    # who owns the mapping.
    extra_str = ''

    if ptep & iommu_flag:
        # The mapping is an IOMMU Mapping
        ptep = ptep & ~iommu_flag

        # Due to LLDB automatically setting all the high bits of pointers, when
        # ptep is retrieved from the pve_ptep[] array, LLDB will automatically set
        # the iommu_table_flag, which means this check only works for PVH entries
        # of type PVH_TYPE_PTEP (since those PTEPs come directly from the PVH
        # entry which has the right casting applied to avoid this issue).
        #
        # Why don't we just do the same casting for pve_ptep[] you ask? Well not
        # for a lack of trying, that's for sure. If you can figure out how to
        # cast that array correctly, then be my guest.
        if kern.globals.page_protection_type <= kern.PAGE_PROTECTION_TYPE_PPL:
            if ptep & iommu_table_flag:
                pte_str = ' (IOMMU table), entry'
                ptd = GetPtDesc(KVToPhysARM(ptep))
                iommu = dereference(ptd.iommu)
            else:
                # Instead of dumping the PTE (since we don't have that), dump the
                # descriptor object used by the IOMMU state (t8020dart/nvme_ppl/etc).
                #
                # This works because later on when the "ptep" is dereferenced as a
                # PTE pointer (uint64_t pointer), the descriptor pointer will be
                # dumped as that's the first 64-bit value in the IOMMU state object.
                pte_str = ' (IOMMU state), descriptor'
                ptep = ptep | iommu_table_flag
                iommu = dereference(kern.GetValueFromAddress(ptep, 'ppl_iommu_state *'))

            # For IOMMU mappings, dump who owns the mapping as the extra string.
            extra_str = 'Mapped by {:s}'.format(dereference(iommu.desc).name)
            if unsigned(iommu.name) != 0:
                extra_str += '/{:s}'.format(iommu.name)
            extra_str += ' (iommu state: {:x})'.format(addressof(iommu))
        else:
            ptd = GetPtDesc(KVToPhysARM(ptep))
            extra_str = 'Mapped by IOMMU {:x}'.format(ptd.iommu)
    else:
        # The mapping is a CPU Mapping
        pte_str += ', entry'
        ptd = GetPtDesc(KVToPhysARM(ptep))
        if ptd.pmap == kern.globals.kernel_pmap:
            extra_str = "Mapped by kernel task (kernel_pmap: {:#x})".format(ptd.pmap)
        elif verbose_level >= vDETAIL:
            task = TaskForPmapHelper(ptd.pmap)
            extra_str = "Mapped by user task (pmap: {:#x}, task: {:s})".format(ptd.pmap, "{:#x}".format(task) if task is not None else "<unknown>")
    try:
        print("{:s}PTEP {:#x}{:s}: {:#x}".format(pve_str, ptep, pte_str, dereference(kern.GetValueFromAddress(ptep, 'pt_entry_t *'))))
    except:
        print("{:s}PTEP {:#x}{:s}: <unavailable>".format(pve_str, ptep, pte_str))

    if verbose_level >= vDETAIL:
        print("    |-- {:s}".format(extra_str))

def PVWalkARM(pai, verbose_level = vHUMAN):
    """ Walk a physical-to-virtual reverse mapping list maintained by the arm pmap.

        pai: physical address index (PAI) corresponding to the pv_head_table
             entry to walk.
        verbose_level: Set to vSCRIPT or higher to print extra info around the
                       the pv_head_table/pp_attr_table flags and to dump the
                       pt_desc_t object if the type is a PTD.
    """
    # LLDB will automatically try to make pointer values dereferencable by
    # setting the upper bits if they aren't set. We need to parse the flags
    # stored in the upper bits later, so cast the pv_head_table to an array of
    # integers to get around this "feature". We'll add the upper bits back
    # manually before deref'ing anything.
    pv_head_table = cast(kern.GetGlobalVariable('pv_head_table'), "uintptr_t*")
    pvh_raw = unsigned(pv_head_table[pai])
    pvh = pvh_raw
    pvh_type = pvh & 0x3

    print("PVH raw value: {:#x}".format(pvh_raw))
    if kern.arch.startswith('arm64'):
        pvh = pvh | PVH_HIGH_FLAGS_ARM64
    else:
        pvh = pvh | PVH_HIGH_FLAGS_ARM32

    if pvh_type == 0:
        print("PVH type: NULL")
    elif pvh_type == 3:
        print("PVH type: page-table descriptor ({:#x})".format(pvh & ~0x3))
    elif pvh_type == 2:
        print("PVH type: single PTE")
        PVDumpPTE(None, pvh, verbose_level)
    elif pvh_type == 1:
        pvep = pvh & ~0x3
        print("PVH type: PTE list")
        pve_ptep_idx = 0
        while pvep != 0:
            pve = kern.GetValueFromAddress(pvep, "pv_entry_t *")

            if pve.pve_ptep[pve_ptep_idx] != 0:
                PVDumpPTE(pvep, pve.pve_ptep[pve_ptep_idx], verbose_level)

            pve_ptep_idx += 1
            if pve_ptep_idx == 2:
                pve_ptep_idx = 0
                pvep = unsigned(pve.pve_next)

    if verbose_level >= vDETAIL:
        if (pvh_type == 1) or (pvh_type == 2):
            # Dump pv_head_table flags when there's a valid mapping.
            pvh_flags = []

            if pvh_raw & (1 << 62):
                pvh_flags.append("CPU")
            if pvh_raw & (1 << 60):
                pvh_flags.append("EXEC")
            if pvh_raw & (1 << 59):
                pvh_flags.append("LOCKDOWN_KC")
            if pvh_raw & (1 << 58):
                pvh_flags.append("HASHED")
            if pvh_raw & (1 << 57):
                pvh_flags.append("LOCKDOWN_CS")
            if pvh_raw & (1 << 56):
                pvh_flags.append("LOCKDOWN_RO")
            if pvh_raw & (1 << 55):
                pvh_flags.append("RETIRED")
            if pvh_raw & (1 << 54):
                if kern.globals.page_protection_type > kern.PAGE_PROTECTION_TYPE_PPL:
                    pvh_flags.append("SLEEPABLE_LOCK")
            if pvh_raw & (1 << 52):
                if kern.globals.page_protection_type <= kern.PAGE_PROTECTION_TYPE_PPL:
                    pvh_flags.append("SECURE_FLUSH_NEEDED")
            if kern.arch.startswith('arm64') and pvh_raw & (1 << 61):
                pvh_flags.append("LOCK")

            print("PVH Flags: {}".format(pvh_flags))

        # Always dump pp_attr_table flags (these can be updated even if there aren't mappings).
        ppattr = unsigned(kern.globals.pp_attr_table[pai])
        print("PPATTR raw value: {:#x}".format(ppattr))

        ppattr_flags = ["WIMG ({:#x})".format(ppattr & 0x3F)]
        if ppattr & 0x40:
            ppattr_flags.append("REFERENCED")
        if ppattr & 0x80:
            ppattr_flags.append("MODIFIED")
        if ppattr & 0x100:
            ppattr_flags.append("INTERNAL")
        if ppattr & 0x200:
            ppattr_flags.append("REUSABLE")
        if ppattr & 0x400:
            ppattr_flags.append("ALTACCT")
        if ppattr & 0x800:
            ppattr_flags.append("NOENCRYPT")
        if ppattr & 0x1000:
            ppattr_flags.append("REFFAULT")
        if ppattr & 0x2000:
            ppattr_flags.append("MODFAULT")
        if ppattr & 0x4000:
            ppattr_flags.append("MONITOR")
        if ppattr & 0x8000:
            ppattr_flags.append("NO_MONITOR")

        print("PPATTR Flags: {}".format(ppattr_flags))

        if pvh_type == 3:
            def RunLldbCmdHelper(command):
                """Helper for dumping an LLDB command right before executing it
                and printing the results.
                command: The LLDB command (as a string) to run.

                Example input: "p/x kernel_pmap".
                """
                print("\nExecuting: {:s}\n{:s}".format(command, lldb_run_command(command)))
            # Dump the page table descriptor object
            ptd = kern.GetValueFromAddress(pvh & ~0x3, 'pt_desc_t *')
            RunLldbCmdHelper("p/x *(pt_desc_t*)" + hex(ptd))

            # Depending on the system, more than one ptd_info can be associated
            # with a single PTD. Only dump the first PTD info and assume the
            # user knows to dump the rest if they're on one of those systems.
            RunLldbCmdHelper("p/x ((pt_desc_t*)" + hex(ptd) + ")->ptd_info[0]")

@lldb_command('pv_walk')
def PVWalk(cmd_args=None):
    """ Show mappings for <physical_address | PAI> tracked in the PV list.
        Syntax: (lldb) pv_walk <physical_address | PAI> [-vv]

        Extra verbosity will pretty print the pv_head_table/pp_attr_table flags
        as well as dump the page table descriptor (PTD) struct if the entry is a
        PTD.
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Too few arguments to pv_walk.")
    if not kern.arch.startswith('arm'):
        raise NotImplementedError("pv_walk does not support {0}".format(kern.arch))

    pa = kern.GetValueFromAddress(cmd_args[0], 'unsigned long')

    # If the input is already a PAI, this function will return the input unchanged.
    # This function also ensures that the physical address is kernel-managed.
    pai = ConvertPhysAddrToPai(pa)

    PVWalkARM(pai, config['verbosity'])

@lldb_command('kvtophys')
def KVToPhys(cmd_args=None):
    """ Translate a kernel virtual address to the corresponding physical address.
        Assumes the virtual address falls within the kernel static region.
        Syntax: (lldb) kvtophys <kernel virtual address>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Too few arguments to kvtophys.")
    if kern.arch.startswith('arm'):
        print("{:#x}".format(KVToPhysARM(int(unsigned(kern.GetValueFromAddress(cmd_args[0], 'unsigned long'))))))
    elif kern.arch == 'x86_64':
        print("{:#x}".format(int(unsigned(kern.GetValueFromAddress(cmd_args[0], 'unsigned long'))) - unsigned(kern.globals.physmap_base)))

@lldb_command('phystokv')
def PhysToKV(cmd_args=None):
    """ Translate a physical address to the corresponding static kernel virtual address.
        Assumes the physical address corresponds to managed DRAM.
        Syntax: (lldb) phystokv <physical address>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Too few arguments to phystokv.")
    print("{:#x}".format(kern.PhysToKernelVirt(int(unsigned(kern.GetValueFromAddress(cmd_args[0], 'unsigned long'))))))

def KVToPhysARM(addr):
    if kern.globals.page_protection_type <= kern.PAGE_PROTECTION_TYPE_PPL:
        ptov_table = kern.globals.ptov_table
        for i in range(0, kern.globals.ptov_index):
            if (addr >= int(unsigned(ptov_table[i].va))) and (addr < (int(unsigned(ptov_table[i].va)) + int(unsigned(ptov_table[i].len)))):
                return (addr - int(unsigned(ptov_table[i].va)) + int(unsigned(ptov_table[i].pa)))
    else:
        papt_table = kern.globals.libsptm_papt_ranges
        page_size = kern.globals.page_size
        for i in range(0, kern.globals.libsptm_n_papt_ranges):
            if (addr >= int(unsigned(papt_table[i].papt_start))) and (addr < (int(unsigned(papt_table[i].papt_start)) + int(unsigned(papt_table[i].num_mappings) * page_size))):
                return (addr - int(unsigned(papt_table[i].papt_start)) + int(unsigned(papt_table[i].paddr_start)))
        raise ValueError("VA {:#x} not found in physical region lookup table".format(addr))
    return (addr - unsigned(kern.globals.gVirtBase) + unsigned(kern.globals.gPhysBase))


def GetPtDesc(paddr):
    pn = (paddr - unsigned(kern.globals.vm_first_phys)) // kern.globals.page_size
    pvh = unsigned(kern.globals.pv_head_table[pn])
    if kern.arch.startswith('arm64'):
        pvh = pvh | PVH_HIGH_FLAGS_ARM64
    else:
        pvh = pvh | PVH_HIGH_FLAGS_ARM32
    pvh_type = pvh & 0x3
    if pvh_type != 0x3:
        raise ValueError("PV head {:#x} does not correspond to a page-table descriptor".format(pvh))
    ptd = kern.GetValueFromAddress(pvh & ~0x3, 'pt_desc_t *')
    return ptd

def PhysToFrameTableEntry(paddr):
    if paddr >= int(unsigned(kern.globals.sptm_first_phys)) or paddr < int(unsigned(kern.globals.sptm_last_phys)):
        return kern.globals.frame_table[(paddr - int(unsigned(kern.globals.sptm_first_phys))) // kern.globals.page_size]
    page_idx = paddr / kern.globals.page_size
    for i in range(0, kern.globals.sptm_n_io_ranges):
        base = kern.globals.io_frame_table[i].io_range.phys_page_idx
        end = base + kern.globals.io_frame_table[i].io_range.num_pages
        if page_idx >= base and page_idx < end:
            return kern.globals.io_frame_table[i]
    return kern.globals.xnu_io_fte

@lldb_command('phystofte')
def PhysToFTE(cmd_args=None):
    """ Translate a physical address to the corresponding SPTM frame table entry pointer
        Syntax: (lldb) phystofte <physical address>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Too few arguments to phystofte.")

    fte = PhysToFrameTableEntry(int(unsigned(kern.GetValueFromAddress(cmd_args[0], 'unsigned long'))))
    print(repr(fte))

XNU_IOMMU = 23
XNU_PAGE_TABLE = 19
XNU_PAGE_TABLE_SHARED = 20
XNU_PAGE_TABLE_ROZONE = 21
XNU_PAGE_TABLE_COMMPAGE = 22
SPTM_PAGE_TABLE = 9

def ShowPTEARM(pte, page_size, level):
    """ Display vital information about an ARM page table entry
        pte: kernel virtual address of the PTE.  page_size and level may be None,
        in which case we'll try to infer them from the page table descriptor.
        Inference of level may only work for L2 and L3 TTEs depending upon system
        configuration.
    """
    pt_index = 0
    stage2 = False
    def GetPageTableInfo(ptd, paddr):
        nonlocal pt_index, page_size, level
        if kern.globals.page_protection_type <= kern.PAGE_PROTECTION_TYPE_PPL:
            # First load ptd_info[0].refcnt so that we can check if this is an IOMMU page.
            # IOMMUs don't split PTDs across multiple 4K regions as CPU page tables sometimes
            # do, so the IOMMU refcnt token is always stored at index 0.  If this is not
            # an IOMMU page, we may end up using a different final value for pt_index below.
            refcnt = ptd.ptd_info[0].refcnt
            # PTDs used to describe IOMMU pages always have a refcnt of 0x8000/0x8001.
            is_iommu_pte = (refcnt & 0x8000) == 0x8000
            if not is_iommu_pte and page_size is None and hasattr(ptd.pmap, 'pmap_pt_attr'):
                page_size = ptd.pmap.pmap_pt_attr.pta_page_size
            elif page_size is None:
                page_size = kern.globals.native_pt_attr.pta_page_size
            pt_index = (pte % kern.globals.page_size) // page_size
            refcnt =  ptd.ptd_info[pt_index].refcnt
            if not is_iommu_pte and hasattr(ptd.pmap, 'pmap_pt_attr') and hasattr(ptd.pmap.pmap_pt_attr, 'stage2'):
                stage2 = ptd.pmap.pmap_pt_attr.stage2
            if level is None:
                if refcnt == 0x4000:
                    level = 2
                else:
                    level = 3
            if is_iommu_pte:
                iommu_desc_name = '{:s}'.format(dereference(dereference(ptd.iommu).desc).name)
                if unsigned(dereference(ptd.iommu).name) != 0:
                    iommu_desc_name += '/{:s}'.format(dereference(ptd.iommu).name)
                info_str = "iommu state: {:#x} ({:s})".format(ptd.iommu, iommu_desc_name)
            else:
                info_str = None
            return (int(unsigned(refcnt)), level, info_str)
        else:
            fte = PhysToFrameTableEntry(paddr)
            if fte.type == XNU_IOMMU:
                if page_size is None:
                    page_size = kern.globals.native_pt_attr.pta_page_size
                info_str = "PTD iommu token: {:#x} (ID {:#x} TSD {:#x})".format(ptd.iommu, fte.iommu_page.iommu_id, fte.iommu_page.iommu_tsd)
                return (int(unsigned(fte.iommu_page.iommu_refcnt._value)), 0, info_str)
            elif fte.type in [XNU_PAGE_TABLE, XNU_PAGE_TABLE_SHARED, XNU_PAGE_TABLE_ROZONE, XNU_PAGE_TABLE_COMMPAGE, SPTM_PAGE_TABLE]:
                if page_size is None:
                    if hasattr(ptd.pmap, 'pmap_pt_attr'):
                        page_size = ptd.pmap.pmap_pt_attr.pta_page_size
                    else:
                        page_size = kern.globals.native_pt_attr.pta_page_size;
                return (int(unsigned(fte.cpu_page_table.mapping_refcnt._value)), int(unsigned(fte.cpu_page_table.level)), None)
            else:
                raise ValueError("Unrecognized FTE type {:#x}".format(fte.type))
            raise ValueError("Unable to retrieve PTD refcnt")
    pte_paddr = KVToPhysARM(pte)
    ptd = GetPtDesc(pte_paddr)
    refcnt, level, info_str = GetPageTableInfo(ptd, pte_paddr)
    wiredcnt = ptd.ptd_info[pt_index].wiredcnt
    if kern.globals.page_protection_type <= kern.PAGE_PROTECTION_TYPE_PPL:
        va = ptd.va[pt_index]
    else:
        va = ptd.va
    print("descriptor: {:#x} (refcnt: {:#x}, wiredcnt: {:#x}, va: {:#x})".format(ptd, refcnt, wiredcnt, va))

    # The pmap/iommu field is a union, so only print the correct one.
    if info_str is not None:
        print(info_str)
    else:
        if ptd.pmap == kern.globals.kernel_pmap:
            pmap_str = "(kernel_pmap)"
        else:
            task = TaskForPmapHelper(ptd.pmap)
            pmap_str = "(User Task: {:s})".format("{:#x}".format(task) if task is not None else "<unknown>")
        print("pmap: {:#x} {:s}".format(ptd.pmap, pmap_str))
        nttes = page_size // 8
        granule = page_size * (nttes ** (3 - level))
        if kern.globals.page_protection_type <= kern.PAGE_PROTECTION_TYPE_PPL:
            pte_pgoff = pte % page_size
        else:
            pte_pgoff = pte % kern.globals.native_pt_attr.pta_page_size
        pte_pgoff = pte_pgoff // 8
        print("maps {}: {:#x}".format("IPA" if stage2 else "VA", int(unsigned(va)) + (pte_pgoff * granule)))
        pteval = int(unsigned(dereference(kern.GetValueFromAddress(unsigned(pte), 'pt_entry_t *'))))
        print("value: {:#x}".format(pteval))
        print("level: {:d}".format(level))
        PmapDecodeTTEARM64(pteval, level, stage2)

@lldb_command('showpte')
def ShowPTE(cmd_args=None):
    """ Display vital information about the page table entry at VA <pte>
        Syntax: (lldb) showpte <pte_va> [level] [4k|16k|16k_s2]
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Too few arguments to showpte.")

    if kern.arch.startswith('arm64'):
        if len(cmd_args) >= 3:
            pmap_pt_attr = GetMemoryAttributesFromUser(cmd_args[2])
            if pmap_pt_attr is None:
                raise ArgumentError("Invalid translation attribute type.")
            page_size = pmap_pt_attr.pta_page_size
        else:
            page_size = None

        level = ArgumentStringToInt(cmd_args[1]) if len(cmd_args) >= 2 else None
        ShowPTEARM(kern.GetValueFromAddress(cmd_args[0], 'unsigned long'), page_size, level)
    else:
        raise NotImplementedError("showpte does not support {0}".format(kern.arch))

def FindMappingAtLevelARM64(pmap, tt, nttes, level, va, action):
    """ Perform the specified action for all valid mappings in an ARM64 translation table
        pmap: owner of the translation table
        tt: translation table or page table
        nttes: number of entries in tt
        level: translation table level, 1 2 or 3
        action: callback for each valid TTE
    """
    # Obtain pmap attributes
    pmap_pt_attr = pmap.pmap_pt_attr if hasattr(pmap, 'pmap_pt_attr') else kern.globals.native_pt_attr
    page_size = pmap_pt_attr.pta_page_size
    page_offset_mask = (page_size - 1)
    page_base_mask = ((1 << ARM64_VMADDR_BITS) - 1) & (~page_offset_mask)
    max_level = unsigned(pmap_pt_attr.pta_max_level)

    for i in range(nttes):
        try:
            tte = tt[i]
            if tte & 0x1 == 0x0:
                continue

            tt_next = None
            paddr = unsigned(tte) & unsigned(page_base_mask)

            # Handle leaf entry
            if tte & 0x2 == 0x0 or level == max_level:
                type = 'block' if level < max_level else 'entry'
                granule = PmapBlockOffsetMaskARM64(page_size, level) + 1
            else:
            # Handle page table entry
                type = 'table'
                granule = page_size
                tt_next = kern.GetValueFromAddress(kern.PhysToKernelVirt(paddr), 'tt_entry_t *')

            mapped_va = int(unsigned(va)) + ((PmapBlockOffsetMaskARM64(page_size, level) + 1) * i)
            if action(pmap, level, type, addressof(tt[i]), paddr, mapped_va, granule):
                if tt_next is not None:
                    FindMappingAtLevelARM64(pmap, tt_next, granule // ARM64_TTE_SIZE, level + 1, mapped_va, action)

        except Exception as exc:
            print("Unable to access tte {:#x}".format(unsigned(addressof(tt[i])))) 

def ScanPageTables(action, targetPmap=None):
    """ Perform the specified action for all valid mappings in all page tables,
        optionally restricted to a single pmap.
        pmap: pmap whose page table should be scanned.  If None, all pmaps on system will be scanned.
    """
    print("Scanning all available translation tables.  This may take a long time...")
    def ScanPmap(pmap, action):
        if kern.arch.startswith('arm64'):
            # Obtain pmap attributes
            pmap_pt_attr = pmap.pmap_pt_attr if hasattr(pmap, 'pmap_pt_attr') else kern.globals.native_pt_attr
            granule = pmap_pt_attr.pta_page_size
            level = unsigned(pmap_pt_attr.pta_root_level)
            root_pgtable_num_ttes = (unsigned(pmap_pt_attr.pta_level_info[level].index_mask) >> \
                unsigned(pmap_pt_attr.pta_level_info[level].shift)) + 1

        if action(pmap, pmap_pt_attr.pta_root_level, 'root', pmap.tte, unsigned(pmap.ttep), pmap.min, granule):
            if kern.arch.startswith('arm64'):
                FindMappingAtLevelARM64(pmap, pmap.tte, root_pgtable_num_ttes, level, pmap.min, action)

    if targetPmap is not None:
        ScanPmap(kern.GetValueFromAddress(targetPmap, 'pmap_t'), action)
    else:
        for pmap in IterateQueue(kern.globals.map_pmap_list, 'pmap_t', 'pmaps'):
            ScanPmap(pmap, action)        

@lldb_command('showallmappings')
def ShowAllMappings(cmd_args=None):
    """ Find and display all available mappings on the system for
        <physical_address>.  Optionally only searches the pmap
        specified by [<pmap>]
        Syntax: (lldb) showallmappings <physical_address> [<pmap>]
        WARNING: this macro can take a long time (up to 30min.) to complete!
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Too few arguments to showallmappings.")
    if not kern.arch.startswith('arm'):
        raise NotImplementedError("showallmappings does not support {0}".format(kern.arch))
    pa = kern.GetValueFromAddress(cmd_args[0], 'unsigned long')
    targetPmap = None
    if len(cmd_args) > 1:
        targetPmap = cmd_args[1]
    def printMatchedMapping(pmap, level, type, tte, paddr, va, granule):
        if paddr <= pa < (paddr + granule):
            print("pmap: {:#x}: L{:d} {:s} at {:#x}: [{:#x}, {:#x}), maps va {:#x}".format(pmap, level, type, unsigned(tte), paddr, paddr + granule, va))
        return True
    ScanPageTables(printMatchedMapping, targetPmap)

@lldb_command('showptusage')
def ShowPTUsage(cmd_args=None):
    """ Display a summary of pagetable allocations for a given pmap.
        Syntax: (lldb) showptusage [<pmap>]
        WARNING: this macro can take a long time (> 1hr) to complete!
    """
    if not kern.arch.startswith('arm'):
        raise NotImplementedError("showptusage does not support {0}".format(kern.arch))
    targetPmap = None
    if len(cmd_args) > 0:
        targetPmap = cmd_args[0]
    lastPmap = [None]
    numTables = [0]
    numUnnested = [0]
    numPmaps = [0]
    def printValidTTE(pmap, level, type, tte, paddr, va, granule):
        unnested = ""
        nested_region_addr = int(unsigned(pmap.nested_region_addr))
        nested_region_end = nested_region_addr + int(unsigned(pmap.nested_region_size))
        if lastPmap[0] is None or (pmap != lastPmap[0]):
            lastPmap[0] = pmap
            numPmaps[0] = numPmaps[0] + 1
            print ("pmap {:#x}:".format(pmap))
        if type == 'root':
            return True
        if (level == 2) and (va >= nested_region_addr) and (va < nested_region_end):
            ptd = GetPtDesc(paddr)
            if ptd.pmap != pmap:
                return False
            else:
                numUnnested[0] = numUnnested[0] + 1
                unnested = " (likely unnested)"
        numTables[0] = numTables[0] + 1
        print((" " * 4 * int(level)) + "L{:d} entry at {:#x}, maps {:#x}".format(level, unsigned(tte), va) + unnested)
        if level == 2:
            return False
        else:
            return True
    ScanPageTables(printValidTTE, targetPmap)
    print("{:d} table(s), {:d} of them likely unnested, in {:d} pmap(s)".format(numTables[0], numUnnested[0], numPmaps[0]))

def checkPVList(pmap, level, type, tte, paddr, va, granule):
    """ Checks an ARM physical-to-virtual mapping list for consistency errors.
        pmap: owner of the translation table
        level: translation table level.  PV lists will only be checked for L2 (arm32) or L3 (arm64) tables.
        type: unused
        tte: KVA of PTE to check for presence in PV list.  If None, presence check will be skipped.
        paddr: physical address whose PV list should be checked.  Need not be page-aligned.
        granule: unused
    """
    vm_first_phys = unsigned(kern.globals.vm_first_phys)
    vm_last_phys = unsigned(kern.globals.vm_last_phys)
    page_size = kern.globals.page_size
    if kern.arch.startswith('arm64'):
        page_offset_mask = (page_size - 1)
        page_base_mask = ((1 << ARM64_VMADDR_BITS) - 1) & (~page_offset_mask)
        paddr = paddr & page_base_mask
        max_level = 3
        pvh_set_bits = PVH_HIGH_FLAGS_ARM64
    if level < max_level or paddr < vm_first_phys or paddr >= vm_last_phys:
        return True
    pn = (paddr - vm_first_phys) // page_size
    pvh = unsigned(kern.globals.pv_head_table[pn]) | pvh_set_bits
    pvh_type = pvh & 0x3
    if pmap is not None:
        pmap_str = "pmap: {:#x}: ".format(pmap)
    else:
        pmap_str = ''
    if tte is not None:
        tte_str = "pte {:#x} ({:#x}): ".format(unsigned(tte), paddr)
    else:
        tte_str = "paddr {:#x}: ".format(paddr) 
    if pvh_type == 0 or pvh_type == 3:
        print("{:s}{:s}unexpected PVH type {:d}".format(pmap_str, tte_str, pvh_type))
    elif pvh_type == 2:
        ptep = pvh & ~0x3
        if tte is not None and ptep != unsigned(tte):
            print("{:s}{:s}PVH mismatch ({:#x})".format(pmap_str, tte_str, ptep))
        try:
            pte = int(unsigned(dereference(kern.GetValueFromAddress(ptep, 'pt_entry_t *')))) & page_base_mask 
            if (pte != paddr):
                print("{:s}{:s}PVH {:#x} maps wrong page ({:#x}) ".format(pmap_str, tte_str, ptep, pte))
        except Exception as exc:
            print("{:s}{:s}Unable to read PVH {:#x}".format(pmap_str, tte_str, ptep))
    elif pvh_type == 1:
        pvep = pvh & ~0x3
        tte_match = False
        pve_ptep_idx = 0
        while pvep != 0:
            pve = kern.GetValueFromAddress(pvep, "pv_entry_t *")
            ptep = unsigned(pve.pve_ptep[pve_ptep_idx]) & ~0x3
            pve_ptep_idx += 1
            if pve_ptep_idx == 2:
                pve_ptep_idx = 0
                pvep = unsigned(pve.pve_next)
            if ptep == 0:
                continue
            if tte is not None and ptep == unsigned(tte):
                tte_match = True
            try:
                pte = int(unsigned(dereference(kern.GetValueFromAddress(ptep, 'pt_entry_t *')))) & page_base_mask 
                if (pte != paddr):
                    print("{:s}{:s}PVE {:#x} maps wrong page ({:#x}) ".format(pmap_str, tte_str, ptep, pte))
            except Exception as exc:
                print("{:s}{:s}Unable to read PVE {:#x}".format(pmap_str, tte_str, ptep))
        if tte is not None and not tte_match:
            print("{:s}{:s}{:s}not found in PV list".format(pmap_str, tte_str, paddr))
    return True

@lldb_command('pv_check', 'P')
def PVCheck(cmd_args=None, cmd_options={}):
    """ Check the physical-to-virtual mapping for a given PTE or physical address
        Syntax: (lldb) pv_check <addr> [-p]
            -P        : Interpret <addr> as a physical address rather than a PTE
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Too few arguments to pv_check.")
    if kern.arch.startswith('arm64'):
        level = 3
    else:
        raise NotImplementedError("pv_check does not support {0}".format(kern.arch))
    if "-P" in cmd_options:
        pte = None
        pa = int(unsigned(kern.GetValueFromAddress(cmd_args[0], "unsigned long")))
    else:
        pte = kern.GetValueFromAddress(cmd_args[0], 'pt_entry_t *')
        pa = int(unsigned(dereference(pte)))
    checkPVList(None, level, None, pte, pa, 0, None)

@lldb_command('check_pmaps')
def CheckPmapIntegrity(cmd_args=None):
    """ Performs a system-wide integrity check of all PTEs and associated PV lists.
        Optionally only checks the pmap specified by [<pmap>]
        Syntax: (lldb) check_pmaps [<pmap>]
        WARNING: this macro can take a HUGE amount of time (several hours) if you do not
        specify [pmap] to limit it to a single pmap.  It will also give false positives
        for kernel_pmap, as we do not create PV entries for static kernel mappings on ARM.
        Use of this macro without the [<pmap>] argument is heavily discouraged.
    """
    if not kern.arch.startswith('arm'):
        raise NotImplementedError("check_pmaps does not support {0}".format(kern.arch))
    targetPmap = None
    if len(cmd_args) > 0:
        targetPmap = cmd_args[0]
    ScanPageTables(checkPVList, targetPmap)

@lldb_command('pmapsforledger')
def PmapsForLedger(cmd_args=None):
    """ Find and display all pmaps currently using <ledger>.
        Syntax: (lldb) pmapsforledger <ledger>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Too few arguments to pmapsforledger.")
    if not kern.arch.startswith('arm'):
        raise NotImplementedError("pmapsforledger does not support {0}".format(kern.arch))
    ledger = kern.GetValueFromAddress(cmd_args[0], 'ledger_t')
    for pmap in IterateQueue(kern.globals.map_pmap_list, 'pmap_t', 'pmaps'):
        if pmap.ledger == ledger:
            print("pmap: {:#x}".format(pmap))


def IsValidPai(pai):
    """ Given an unsigned value, detect whether that value is a valid physical
        address index (PAI). It does this by first computing the last possible
        PAI and comparing the input to that.

        All contemporary SoCs reserve the bottom part of the address space, so
        there shouldn't be any valid physical addresses between zero and the
        last PAI either.
    """
    page_size = unsigned(kern.globals.page_size)
    vm_first_phys = unsigned(kern.globals.vm_first_phys)
    vm_last_phys = unsigned(kern.globals.vm_last_phys)

    last_pai = (vm_last_phys - vm_first_phys) // page_size
    if (pai < 0) or (pai >= last_pai):
        return False

    return True

def ConvertPaiToPhysAddr(pai):
    """ Convert the given Physical Address Index (PAI) into a physical address.

        If the input isn't a valid PAI (it's most likely already a physical
        address), then just return back the input unchanged.
    """
    pa = pai

    # If the value is a valid PAI, then convert it into a physical address.
    if IsValidPai(pai):
        pa = (pai * unsigned(kern.globals.page_size)) + unsigned(kern.globals.vm_first_phys)

    return pa

def ConvertPhysAddrToPai(pa):
    """ Convert the given physical address into a Physical Address Index (PAI).

        If the input is already a valid PAI, then just return back the input
        unchanged.
    """
    vm_first_phys = unsigned(kern.globals.vm_first_phys)
    vm_last_phys = unsigned(kern.globals.vm_last_phys)
    pai = pa

    if not IsValidPai(pa) and (pa < vm_first_phys or pa >= vm_last_phys):
        raise ArgumentError("{:#x} is neither a valid PAI nor a kernel-managed address: [{:#x}, {:#x})".format(pa, vm_first_phys, vm_last_phys))
    elif not IsValidPai(pa):
        # If the value isn't already a valid PAI, then convert it into one.
        pai = (pa - vm_first_phys) // unsigned(kern.globals.page_size)

    return pai

@lldb_command('pmappaindex')
def PmapPaIndex(cmd_args=None):
    """ Display both a physical address and physical address index (PAI) when
        provided with only one of those values.

        Syntax: (lldb) pmappaindex <physical address | PAI>

        NOTE: This macro will throw an exception if the input isn't a valid PAI
              and is also not a kernel-managed physical address.
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Too few arguments to pmappaindex.")

    if not kern.arch.startswith('arm'):
        raise NotImplementedError("pmappaindex is only supported on ARM devices.")

    value = kern.GetValueFromAddress(cmd_args[0], 'unsigned long')
    pai = value
    phys_addr = value

    if IsValidPai(value):
        # Input is a PAI, calculate the physical address.
        phys_addr = ConvertPaiToPhysAddr(value)
    else:
        # Input is a physical address, calculate the PAI
        pai = ConvertPhysAddrToPai(value)

    print("Physical Address: {:#x}".format(phys_addr))
    print("PAI: {:d}".format(pai))
