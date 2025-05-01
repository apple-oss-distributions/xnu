from collections import namedtuple
from functools import cached_property
import os
import io
from typing import Any, Generator
import core
from uuid import UUID

from core.cvalue import (
    unsigned,
    signed,
    addressof
)
from core.caching import (
    cache_dynamically,
    LazyTarget,
)
from core.io import SBProcessRawIO
from macho import MachOSegment, MemMachO, VisualMachoMap

from xnu import (
    IterateLinkedList,
    lldb_alias,
    lldb_command,
    lldb_run_command,
    lldb_type_summary,
    kern,
    Cast,
    header,
    GetLongestMatchOption,
    debuglog,
    dsymForUUID,
    addDSYM,
    loadDSYM,
    ArgumentError,
    ArgumentStringToInt,
    GetObjectAtIndexFromArray,
    ResolveFSPath,
    uuid_regex,
    GetLLDBThreadForKernelThread,
    CommandOutput
)

import kmemory
import macho
import lldb
import concurrent.futures


#
# Summary of information available about a kext.
#
#   uuid     - UUID of the object
#   vmaddr   - VA of the text segment
#   name     - Name of the kext
#   address  - Kext address
#   segments - Mach-O segments (if available)
#   summary  - OSKextLoadedSummary
#   kmod     - kmod_info_t
class KextSummary:
    def __init__(self, uuid: str, vmaddr, name: str, address: int, segments: list[MachOSegment], summary: core.value):
        self.uuid = uuid
        self.vmaddr = vmaddr
        self.name = name
        self.address = address
        self.segments = segments
        self.summary = summary

    @cached_property
    def kmod(self):
        try:
            kmod = GetKmodWithAddr(unsigned(self.address))
        except ValueError:
            kmod = None

        return kmod

# Segment helpers


def text_segment(segments):
    """ Return TEXT segment if present in the list of first one.
        segments: List of MachOSegment.
    """

    text_segments = {
        s.name: s
        for s in segments
        if s.name in ('__TEXT_EXEC', '__TEXT')
    }

    # Pick text segment based on our prefered order.
    for name in ['__TEXT_EXEC', '__TEXT']:
        if name in text_segments:
            return text_segments[name]

    return segments[0]


def seg_contains(segments, addr):
    """ Returns generator of all segments that contains given address. """

    return (
        s for s in segments
        if s.vmaddr <= addr < (s.vmaddr + s.vmsize)
    )


def sec_contains(sections, addr):
    """ Returns generator of all sections that contains given address. """

    return (
        s for s in sections
        if s.addr <= addr < (s.addr + s.size)
    )

def sbsec_contains(target, sbsections, addr):
    """ Returns generator of all SBSections that contains given address. """

    return (
        s for s in sbsections
        if s.GetLoadAddress(target) <= addr < s.GetLoadAddress(target) + s.GetByteSize()
    )


# Summary helpers

def LoadMachO(address, size):
    """ Parses Mach-O headers in given VA range.

        return: MemMachO instance.
    """

    process = LazyTarget.GetProcess()
    procio = SBProcessRawIO(process, address, size)
    bufio = io.BufferedRandom(procio)
    return macho.MemMachO(bufio)


def IterateKextSummaries(target) -> Generator[KextSummary, Any, None]:
    """ Generator walking over all kext summaries. """

    hdr   = target.chkFindFirstGlobalVariable('gLoadedKextSummaries').Dereference()
    arr   = hdr.GetValueForExpressionPath('.summaries[0]')
    total = hdr.xGetIntegerByName('numSummaries')

    for kext in (core.value(e.AddressOf()) for e in arr.xIterSiblings(0, total)):
        # Load Mach-O segments/sections.
        mobj = LoadMachO(unsigned(kext.address), unsigned(kext.size))

        # Construct kext summary.
        yield KextSummary(
            uuid=GetUUIDSummary(kext.uuid),
            vmaddr=text_segment(mobj.segments).vmaddr,
            name=str(kext.name),
            address=unsigned(kext.address),
            segments=mobj.segments,
            summary=kext
        )


@cache_dynamically
def GetAllKextSummaries(target=None) -> list[KextSummary]:
    """ Return all kext summaries. (cached) """

    return list(IterateKextSummaries(target))


def FindKextSummary(kmod_addr):
    """ Returns summary for given kmod_info_t. """

    for mod in GetAllKextSummaries():
        if mod.address == kmod_addr or mod.vmaddr == kmod_addr:
            return mod

    return None


# Keep this around until DiskImages2 migrate over to new methods above.
def GetKextLoadInformation(addr=0, show_progress=False):
    """ Original wrapper kept for backwards compatibility. """
    if addr:
        return [FindKextSummary(addr)]
    else:
        return GetAllKextSummaries()


@lldb_command('showkextmacho')
def ShowKextMachO(cmd_args=[]):
    """ Show visual Mach-O layout.

        Syntax: (lldb) showkextmacho <name of a kext>
    """
    if len(cmd_args) != 1:
        raise ArgumentError("kext name is missing")

    for kext in GetAllKextSummaries():

        # Skip not matching kexts.
        if kext.name.find(cmd_args[0]) == -1:
            continue

        # Load Mach-O segments/sections.
        mobj = LoadMachO(unsigned(kext.kmod.address), unsigned(kext.kmod.size))

        p = VisualMachoMap(kext.name)
        p.printMachoMap(mobj)
        print(" \n")


_UNKNOWN_UUID = "........-....-....-....-............"


@lldb_type_summary(['uuid_t'])
@header("")
def GetUUIDSummary(uuid):
    """ returns a UUID string in form CA50DA4C-CA10-3246-B8DC-93542489AA26

        uuid - Address of a memory where UUID is stored.
    """

    err = lldb.SBError()
    addr = unsigned(addressof(uuid))
    data = LazyTarget.GetProcess().ReadMemory(addr, 16, err)

    if not err.Success():
        return _UNKNOWN_UUID

    return str(UUID(bytes=data)).upper()


@lldb_type_summary(['kmod_info_t *'])
@header(
    f"{'kmod_info': <20s} {'address': <20s} {'size': <12s} {'id': <5s} {'refs': <5s} {'TEXT exec': <20s} {'size': <15s} "
    f"{'version': <15s} {'name': <30s}"
)
def GetKextSummary(kmod):
    """ returns a string representation of kext information """
    if not kmod:
        return "kmod info missing"
    
    format_string = (
        "{mod: <#020x} {mod.address: <#020x} {mod.size: <#012x} "
        "{mod.id: <5d} {mod.reference_count: <5d} {seg.vmaddr: <#020x} "
        "{seg.vmsize: <#015x} {mod.version: <15s} {mod.name: <30s}"
    )

    # Try to obtain text segment from kext summary
    summary = FindKextSummary(unsigned(kmod.address))
    if summary:
        seg = text_segment(summary.segments)
    else:
        # Fake text segment for pseudo kexts.
        seg = MachOSegment('__TEXT', kmod.address, kmod.size, 0, kmod.size, [])

    return format_string.format(mod=kmod, seg=seg)


def GetKmodWithAddr(addr):
    """ Go through kmod list and find one with begin_addr as addr.
        returns: None if not found else a cvalue of type kmod.
    """

    for kmod in IterateLinkedList(kern.globals.kmod, 'next'):
        if addr == unsigned(kmod.address):
            return kmod

    return None


@lldb_command('showkmodaddr')
def ShowKmodAddr(cmd_args=[]):
    """ Given an address, print the offset and name for the kmod containing it
        Syntax: (lldb) showkmodaddr <addr>
    """
    if len(cmd_args) < 1:
        raise ArgumentError("Insufficient arguments")

    addr = ArgumentStringToInt(cmd_args[0])

    # Find first summary/segment pair that covers given address.
    sumseg = (
        (m, next(seg_contains(m.segments, addr), None))
        for m in GetAllKextSummaries()
    )

    print(GetKextSummary.header)
    for ksum, segment in (t for t in sumseg if t[1] is not None):
        summary = GetKextSummary(ksum.kmod)
        print(summary + " segment: {} offset = {:#0x}".format(
            segment.name, (addr - segment.vmaddr)))

    return True


def GetOSKextVersion(version_num):
    """ returns a string of format 1.2.3x from the version_num
        params: version_num - int
        return: str
    """
    if version_num == -1:
        return "invalid"

    (MAJ_MULT, MIN_MULT) = (1000000000000, 100000000)
    (REV_MULT, STAGE_MULT) = (10000, 1000)

    version = version_num

    vers_major = version // MAJ_MULT
    version = version - (vers_major * MAJ_MULT)

    vers_minor = version // MIN_MULT
    version = version - (vers_minor * MIN_MULT)

    vers_revision = version // REV_MULT
    version = version - (vers_revision * REV_MULT)

    vers_stage = version // STAGE_MULT
    version = version - (vers_stage * STAGE_MULT)

    vers_stage_level = version

    out_str = "%d.%d" % (vers_major, vers_minor)
    if vers_revision > 0:
        out_str += ".%d" % vers_revision
    if vers_stage == 1:
        out_str += "d%d" % vers_stage_level
    if vers_stage == 3:
        out_str += "a%d" % vers_stage_level
    if vers_stage == 5:
        out_str += "b%d" % vers_stage_level
    if vers_stage == 6:
        out_str += "fc%d" % vers_stage_level

    return out_str


def FindKmodNameForAddr(addr):
    """ Given an address, return the name of the kext containing that address.
    """

    names = (
        mod.kmod.name
        for mod in GetAllKextSummaries()
        if (any(seg_contains(mod.segments, unsigned(addr))))
    )

    return next(names, None)


@header(
    f"{'UUID': <36s} {GetKextSummary.header}"
)
@lldb_command('showallkmods', fancy=True)
def ShowAllKexts(cmd_args=None, cmd_options={}, O: CommandOutput=None):
    """ Display a summary listing of all loaded kexts (alias: showallkmods) """

    with O.table(ShowAllKexts.header):
        for kmod in IterateLinkedList(kern.globals.kmod, 'next'):
            sum = FindKextSummary(unsigned(kmod.address))

            if sum:
                _ksummary = GetKextSummary(sum.kmod)
                uuid = sum.uuid
            else:
                _ksummary = GetKextSummary(kmod)
                uuid = _UNKNOWN_UUID

            print(uuid + " " + _ksummary)


@lldb_command('showallknownkmods')
def ShowAllKnownKexts(cmd_args=None):
    """ Display a summary listing of all kexts known in the system.
        This is particularly useful to find if some kext was unloaded
        before this crash'ed state.
    """
    kext_ptr = kern.globals.sKextsByID
    kext_count = unsigned(kext_ptr.count)

    print("%d kexts in sKextsByID:" % kext_count)
    print("{0: <20s} {1: <20s} {2: >5s} {3: >20s} {4: <30s}".format('OSKEXT *', 'load_addr', 'id', 'version', 'name'))
    format_string = "{0: <#020x} {1: <20s} {2: >5s} {3: >20s} {4: <30s}"

    for kext_dict in (GetObjectAtIndexFromArray(kext_ptr.dictionary, i)
                      for i in range(kext_count)):

        kext_name = str(kext_dict.key.string)
        osk = Cast(kext_dict.value, 'OSKext *')

        load_addr = "------"
        id = "--"

        if int(osk.flags.loaded):
            load_addr = "{0: <#020x}".format(osk.kmod_info)
            id = "{0: >5d}".format(osk.loadTag)

        version_num = signed(osk.version)
        version = GetOSKextVersion(version_num)
        print(format_string.format(osk, load_addr, id, version, kext_name))


def FetchDSYM(kinfo):
    """ Obtains and adds dSYM based on kext summary. """

    # No op for built-in modules.
    kernel_uuid = str(kern.globals.kernel_uuid_string)
    if kernel_uuid == kinfo.uuid:
        print("(built-in)")
        return

    # Obtain and load binary from dSYM.
    print("Fetching dSYM for %s" % kinfo.uuid)
    info = dsymForUUID(kinfo.uuid)
    if info and 'DBGSymbolRichExecutable' in info:
        print("Adding dSYM (%s) for %s" % (kinfo.uuid, info['DBGSymbolRichExecutable']))
        addDSYM(kinfo.uuid, info)
        loadDSYM(kinfo.uuid, kinfo.vmaddr, kinfo.segments)
    else:
        print("Failed to get symbol info for %s" % kinfo.uuid)


def AddKextSymsByFile(filename, slide):
    """ Add kext based on file name and slide. """
    sections = None

    filespec = lldb.SBFileSpec(filename, False)
    print("target modules add \"{:s}\"".format(filename))
    print(lldb_run_command("target modules add \"{:s}\"".format(filename)))

    loaded_module = LazyTarget.GetTarget().FindModule(filespec)
    if loaded_module.IsValid():
        uuid_str = loaded_module.GetUUIDString()
        debuglog("added module {:s} with uuid {:s}".format(filename, uuid_str))

        if slide is None:
            for k in GetAllKextSummaries():
                debuglog(k.uuid)
                if k.uuid.lower() == uuid_str.lower():
                    slide = k.vmaddr
                    sections = k.segments
                    debuglog("found the slide {:#0x} for uuid {:s}".format(k.vmaddr, k.uuid))
    if slide is None:
        raise ArgumentError("Unable to find load address for module described at {:s} ".format(filename))

    if not sections:
        cmd_str = "target modules load --file \"{:s}\" --slide {:s}".format(filename, str(slide))
        debuglog(cmd_str)
    else:
        cmd_str = "target modules load --file \"{:s}\"".format(filename)
        for s in sections:
            cmd_str += " {:s} {:#0x} ".format(s.name, s.vmaddr)
        debuglog(cmd_str)

    lldb.debugger.HandleCommand(cmd_str)

    kern.symbolicator = None
    return True


def AddKextSymsByName(kextname, all=False):
    """ Add kext based on longest name match"""

    kexts = GetLongestMatchOption(kextname, [x.name for x in GetAllKextSummaries()], True)
    if not kexts:
        print("No matching kext found.")
        return False

    if len(kexts) != 1 and not all:
        print("Ambiguous match for name: {:s}".format(kextname))
        if len(kexts) > 0:
            print("Options are:\n\t" + "\n\t".join(kexts))
        return False

    # Load all matching dSYMs
    for sum in GetAllKextSummaries():
        if sum.name in kexts:
            debuglog("matched the kext to name {:s} "
                     "and uuid {:s}".format(sum.name, sum.uuid))
            FetchDSYM(sum)

    kern.symbolicator = None
    return True


def AddKextByAddress(addr: str):
    """ Given an address, load the kext which contains that address """

    match = (
        (kinfo, seg_contains(kinfo.segments, addr))
        for kinfo in GetAllKextSummaries()
        if any(seg_contains(kinfo.segments, addr))
    )

    # Load all kexts which contain given address.
    print(GetKextSummary.header)
    for kinfo, segs in match:
        for s in segs:
            print(f"{GetKextSummary(kinfo.kmod)} segment: {s.name} offset = {(addr - s.vmaddr):0x}")
            FetchDSYM(kinfo)


def AddKextByThread(addr: str):
    """ Given a thread, load all kexts needed to symbolicate its backtrace """

    thread_value = kern.GetValueFromAddress(addr, "thread_t")
    if not thread_value:
        raise ArgumentError(f"Bad thread given ('{addr}') - see doc for expected input")

    thread_lldb_SBThread = GetLLDBThreadForKernelThread(thread_value)

    kexts_needed = dict()
    printed_header = False
    for frame in thread_lldb_SBThread.frames:
        if not frame.name:
            frame_addr = frame.GetPC()

            match = (
                (kinfo, seg_contains(kinfo.segments, frame_addr))
                for kinfo in GetAllKextSummaries()
                if any(seg_contains(kinfo.segments, frame_addr))
            )

            if match and not printed_header:
                print(GetKextSummary.header)
                printed_header = True

            for kinfo, segs in match:
                for s in segs:
                    print(f"{GetKextSummary(kinfo.kmod)} segment: {s.name} offset = {(frame_addr - s.vmaddr):0x}")
                    kexts_needed[kinfo.uuid] = kinfo
    
    print(f"Fetching {len(kexts_needed)} dSyms")
    pool = concurrent.futures.ThreadPoolExecutor()
    for kinfo in kexts_needed.values():
        pool.submit(FetchDSYM, kinfo)
    pool.shutdown(wait=True)


def AddKextByUUID(uuid: str):
    """ Loads the dSym for a specific UUID, or all dSym """

    kernel_uuid = str(kern.globals.kernel_uuid_string).lower()
    load_all_kexts = (uuid == "all")
    if not load_all_kexts and len(uuid_regex.findall(uuid)) == 0:
        raise ArgumentError("Unknown argument {:s}".format(uuid))

    pool = concurrent.futures.ThreadPoolExecutor()
    for sum in GetAllKextSummaries():
        cur_uuid = sum.uuid.lower()
        if load_all_kexts or (uuid == cur_uuid):
            if kernel_uuid != cur_uuid:
                pool.submit(FetchDSYM, sum)
    pool.shutdown(wait=True)

    kern.symbolicator = None


@lldb_command('addkext', 'AF:T:N:')
def AddKextSyms(cmd_args=[], cmd_options={}):
    """ Add kext symbols into lldb.
        This command finds symbols for a uuid and load the required executable
        Usage:
            addkext <uuid> : Load one kext based on uuid. eg. (lldb)addkext 4DD2344C0-4A81-3EAB-BDCF-FEAFED9EB73E
            addkext -F <abs/path/to/executable> : Load kext with executable
            addkext -F <abs/path/to/executable> <load_address> : Load kext with executable at specified load address
            addkext -N <name> : Load one kext that matches the name provided. eg. (lldb) addkext -N corecrypto
            addkext -N <name> -A: Load all kext that matches the name provided. eg. to load all kext with Apple in name do (lldb) addkext -N Apple -A
            addkext -T <thread_address>: Given a thread_t address(e.g. '0xffffffe0cbf18df0'), load all kexts needed to symbolicate its backtrace
            addkext all    : Will load all the kext symbols - SLOW
    """

    # Load kext by file name.
    if "-F" in cmd_options:
        exec_path = cmd_options["-F"]
        exec_full_path = ResolveFSPath(exec_path)
        if not os.path.exists(exec_full_path):
            raise ArgumentError("Unable to resolve {:s}".format(exec_path))

        if not os.path.isfile(exec_full_path):
            raise ArgumentError(
                """Path is {:s} not a filepath.
                Please check that path points to executable.
                For ex. path/to/Symbols/IOUSBFamily.kext/Contents/PlugIns/AppleUSBHub.kext/Contents/MacOS/AppleUSBHub.
                Note: LLDB does not support adding kext based on directory paths like gdb used to.""".format(exec_path))

        slide_value = None
        if cmd_args:
            slide_value = cmd_args[0]
            debuglog("loading slide value from user input {:s}".format(cmd_args[0]))

        return AddKextSymsByFile(exec_full_path, slide_value)

    # Load kext by name.
    if "-N" in cmd_options:
        kext_name = cmd_options["-N"]
        return AddKextSymsByName(kext_name, "-A" in cmd_options)
    
    # Load all kexts needed to symbolicate a thread's backtrace
    if "-T" in cmd_options:
        return AddKextByThread(cmd_options["-T"])

    # Load kexts by UUID or "all"
    if len(cmd_args) < 1:
        raise ArgumentError("No arguments specified.")

    uuid = cmd_args[0].lower()
    return AddKextByUUID(uuid)


@lldb_command('addkextaddr')
def AddKextAddr(cmd_args=[]):
    """ Given an address, load the kext which contains that address
        Syntax: (lldb) addkextaddr <addr>
    """
    if len(cmd_args) < 1:
        raise ArgumentError("Insufficient arguments")

    addr = ArgumentStringToInt(cmd_args[0])
    AddKextByAddress(addr)


class KextMemoryObject(kmemory.MemoryObject):
    """ Describes an object landing in some kext """

    MO_KIND = "kext mach-o"

    def __init__(self, kmem, address, kinfo):
        super().__init__(kmem, address)
        self.kinfo = kinfo
        self.target = kmem.target

    @property
    def object_range(self):
        seg = next(seg_contains(self.kinfo.segments, self.address))
        sec = next(sec_contains(seg.sections, self.address), None)
        if sec:
            return kmemory.MemoryRange(sec.addr, sec.addr + sec.size)
        return kmemory.MemoryRange(seg.vmaddr, seg.vmaddr + seg.vmsize)

    def find_mod_seg_sect(self):
        target  = self.target
        address = self.address

        return next((
            (module, segment, next(sbsec_contains(target, segment, address), None))
            for module in target.module_iter()
            for segment in sbsec_contains(target, module.section_iter(), address)
        ), (None, None, None))

    def describe(self, verbose=False):
        from lldb.utils.symbolication import Symbolicator

        addr    = self.address
        kinfo   = self.kinfo

        sbmod, sbseg, sbsec = self.find_mod_seg_sect()
        if sbmod is None:
            FetchDSYM(kinfo)
            print()
            sbmod, sbseg, sbsec = self.find_mod_seg_sect()

        syms   = Symbolicator.InitWithSBTarget(self.target).symbolicate(addr)
        sym    = next(iter(syms)) if syms else None

        if not sbseg:
            # not really an SBSection but we only need to pretty print 'name'
            # which both have, yay duck typing
            sbseg = next(seg_contains(kinfo.segments, addr), None)

        fmt  = "Kext Symbol Info\n"
        fmt += " kext                 : {kinfo.name} ({kinfo.uuid})\n"
        fmt += " module               : {sbmod.file.basename}\n" if sbmod else ""
        fmt += " section              : {sbseg.name} {sbsec.name}\n" if sbsec else \
               " segment              : {sbseg.name}\n" if sbseg else ""
        fmt += " symbol               : {sym!s}\n" if sym else ""

        print(fmt.format(kinfo=kinfo, sbmod=sbmod, sbseg=sbseg, sbsec=sbsec, sym=sym))


class MainBinaryMemoryObject(kmemory.MemoryObject):
    """ Describes an object landing in the main kernel binary """

    MO_KIND = "kernel mach-o"

    def __init__(self, kmem, address, section):
        super().__init__(kmem, address)
        self.section = section
        self.target = kmem.target

    def _subsection(self):
        return next(sbsec_contains(self.target, self.section, self.address), None)

    @property
    def object_range(self):
        target  = self.target
        section = self._subsection() or self.section
        addr    = section.GetLoadAddress(target)
        size    = section.GetByteSize()
        return kmemory.MemoryRange(addr, addr + size)

    @property
    def module(self):
        return self.target.GetModuleAtIndex(0).GetFileSpec().GetFilename()

    @property
    def uuid(self):
        return self.target.GetModuleAtIndex(0).GetUUIDString()

    def describe(self, verbose=False):
        from lldb.utils.symbolication import Symbolicator

        subsec  = self._subsection()
        syms    = Symbolicator.InitWithSBTarget(self.target).symbolicate(self.address)
        sym     = next(iter(syms)) if syms else None

        fmt  = "Symbol Info\n"
        fmt += " module               : {mo.module}\n"
        fmt += " uuid                 : {mo.uuid}\n"
        fmt += " section              : {mo.section.name} {subsec.name}\n" if subsec else ""
        fmt += " segment              : {mo.section.name}\n" if not subsec else ""
        fmt += " symbol               : {sym}\n" if sym else ""

        print(fmt.format(mo=self, subsec=subsec, sym=sym))


@kmemory.whatis_provider
class KextWhatisProvider(kmemory.WhatisProvider):
    """ Kext ranges whatis provider """

    COST = 100

    def claims(self, address):
        target  = self.target
        mainmod = target.GetModuleAtIndex(0)

        #
        # TODO: surely the kexts can provide a better range check
        #

        return any(
            sbsec_contains(target, mainmod.section_iter(), address)
        ) or any(
            any(seg_contains(kinfo.segments, address))
            for kinfo in GetAllKextSummaries()
        )

    def lookup(self, address):
        target  = self.target
        mainmod = target.GetModuleAtIndex(0)

        section = next(sbsec_contains(target, mainmod.section_iter(), address), None)

        if section:
            return MainBinaryMemoryObject(self.kmem, address, section)

        return KextMemoryObject(self.kmem, address, next(
            kinfo
            for kinfo in GetAllKextSummaries()
            if any(seg_contains(kinfo.segments, address))
        ))


# Aliases for backward compatibility.

lldb_alias('showkmod', 'showkmodaddr')
lldb_alias('showkext', 'showkmodaddr')
lldb_alias('showkextaddr', 'showkmodaddr')
lldb_alias('showallkexts', 'showallkmods')
