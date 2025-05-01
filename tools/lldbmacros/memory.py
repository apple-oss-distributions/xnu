
""" Please make sure you read the README file COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file.
"""
from xnu import *
import sys
import shlex
import math
from utils import *
import xnudefines
from process import *
import macho
import json
from ctypes import c_int64
from operator import itemgetter
from kext import GetUUIDSummary
from kext import FindKmodNameForAddr
from core.iterators import (
     iter_RB_HEAD,
)
import kmemory
    
def get_vme_offset(vme):
    return unsigned(vme.vme_offset) << 12

def get_vme_object(vme):
    """ Return the vm object or submap associated with the entry """
    if vme.is_sub_map:
        return kern.CreateTypedPointerFromAddress(vme.vme_submap << 2, 'struct _vm_map')
    if vme.vme_kernel_object:
        if get_field(vme, 'vme_is_tagged') is not None:
            return kern.globals.kernel_object_tagged
        return kern.globals.kernel_object_default
    kmem   = kmemory.KMem.get_shared()
    packed = unsigned(vme.vme_object_or_delta)
    addr   = kmem.vm_page_packing.unpack(packed)
    if addr:
        return kern.CreateTypedPointerFromAddress(addr, 'struct vm_object')
    return 0

def IterateZPerCPU(root):
    """ obsolete """
    return (value(v) for v in kmemory.ZPercpuValue(root.GetRawSBValue()))

@lldb_command('showzpcpu', "S")
def ShowZPerCPU(cmd_args=None, cmd_options={}):
    """ Routine to show per-cpu zone allocated variables

        Usage: showzpcpu [-S] expression [field]
            -S  : sum the values instead of printing them
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")

    pcpu = LazyTarget.GetTarget().chkCreateValueFromExpression('value', cmd_args[0])
    for t in kmemory.ZPercpuValue(pcpu):
        if len(cmd_args) > 1:
            t = t.GetValueForExpressionPath('.{}'.format(cmd_args[1]))
        if "-S" in cmd_options:
            acc += t.xGetValueAsInteger()
        else:
            print(value(t))

    if "-S" in cmd_options:
        print(acc)

def ZoneName(zone, zone_security):
    """ Formats the name for a given zone
        params:
            zone             - value : A pointer to a zone
            zone_security    - value : A pointer to zone security flags
        returns:
            the formated name for the zone
    """
    names = [ "", "early.", "data.", "data_shared.", "" ]
    return "{:s}{:s}".format(names[int(zone_security.z_kheap_id)], zone.z_name)

def GetZoneByName(name):
    """ Internal function to find a zone by name
    """
    for i in range(1, int(kern.GetGlobalVariable('num_zones'))):
        z = addressof(kern.globals.zone_array[i])
        zs = addressof(kern.globals.zone_security_array[i])
        if ZoneName(z, zs) == name:
            return z
    return None

def PrettyPrintDictionary(d):
    """ Internal function to pretty print a dictionary with string or integer values
        params: The dictionary to print
    """
    for key, value in list(d.items()):
        key += ":"
        if isinstance(value, int):
            print("{:<30s} {: >10d}".format(key, value))
        elif isinstance(value, float):
            print("{:<30s} {: >10.2f}".format(key, value))
        else:
            print("{:<30s} {: >10s}".format(key, value))

# Macro: memstats

kPolicyClearTheDecks = 0x01
kPolicyBallastDrain = 0x02

@lldb_command('memstats', 'J')
def Memstats(cmd_args=None, cmd_options={}):
    """ Prints out a summary of various memory statistics. In particular vm_page_wire_count should be greater than 2K or you are under memory pressure.
        usage: memstats -J
                Output json
    """
    print_json = False
    if "-J" in cmd_options:
        print_json = True

    memstats = {}
    memstats["vm_page_free_count"] = int(kern.globals.vm_page_free_count)
    memstats["vm_page_free_reserved"] = int(kern.globals.vm_page_free_reserved)
    memstats["vm_page_free_min"] = int(kern.globals.vm_page_free_min)
    memstats["vm_page_free_target"] = int(kern.globals.vm_page_free_target)
    memstats["vm_page_active_count"] = int(kern.globals.vm_page_active_count)
    memstats["vm_page_inactive_count"] = int(kern.globals.vm_page_inactive_count)
    memstats["vm_page_inactive_target"] = int(kern.globals.vm_page_inactive_target)
    memstats["vm_page_wire_count"] = int(kern.globals.vm_page_wire_count)
    memstats["vm_page_purgeable_count"] = int(kern.globals.vm_page_purgeable_count)
    memstats["vm_page_anonymous_count"] = int(kern.globals.vm_page_anonymous_count)
    memstats["vm_page_external_count"] = int(kern.globals.vm_page_external_count)
    memstats["vm_page_xpmapped_ext_count"] = int(kern.globals.vm_page_xpmapped_external_count)
    memstats["vm_page_xpmapped_min"] = int(kern.globals.vm_pageout_state.vm_page_xpmapped_min)
    memstats["vm_page_pageable_ext_count"] = int(kern.globals.vm_page_pageable_external_count)
    memstats["vm_page_filecache_min"] = int(kern.globals.vm_pageout_state.vm_page_filecache_min)
    memstats["vm_page_pageable_int_count"] = int(kern.globals.vm_page_pageable_internal_count)
    memstats["vm_page_throttled_count"] = int(kern.globals.vm_page_throttled_count)
    if hasattr(kern.globals, 'compressor_object'):
        memstats["compressor_count"] = int(kern.globals.compressor_object.resident_page_count)
        memstats["compressed_count"] = int(kern.globals.c_segment_pages_compressed)
        if memstats["compressor_count"] > 0:
            memstats["compression_ratio"] = memstats["compressed_count"] / memstats["compressor_count"]
        else:
            memstats["compression_ratio"] = 0
    memstats["memorystatus_level"] = int(kern.globals.memorystatus_level)
    memstats["memorystatus_available_pages"] = int(kern.globals.memorystatus_available_pages)
    memstats["memorystatus_available_pages_critical"] = int(kern.globals.memstat_critical_threshold)
    memstats["memorystatus_available_pages_idle"] = int(kern.globals.memstat_idle_threshold)
    memstats["memorystatus_available_pages_soft"] = int(kern.globals.memstat_soft_threshold)
    if kern.globals.memstat_policy_config & kPolicyClearTheDecks:
        memstats["memorystatus_clear_the_decks_offset"] = int(kern.globals.memstat_ctd_offset)
    else:
        memstats["memorystatus_clear_the_decks_offset"] = 0
    if kern.globals.memstat_policy_config & kPolicyBallastDrain:
        memstats["memorystatus_ballast_offset"] = int(kern.globals.memstat_ballast_offset)
    else:
        memstats["memorystatus_ballast_offset"] = 0

    try:
        memstats["inuse_ptepages_count"] = int(kern.globals.inuse_ptepages_count)
    except AttributeError:
        pass

    # Serializing to json here ensure we always catch bugs preventing
    # serialization
    as_json = json.dumps(memstats)
    if print_json:
        print(as_json)
    else:
        PrettyPrintDictionary(memstats)

@xnudebug_test('test_memstats')
def TestMemstats(kernel_target, config, lldb_obj, isConnected ):
    """ Test the functionality of memstats command
        returns
         - False on failure
         - True on success
    """
    if not isConnected:
        print("Target is not connected. Cannot test memstats")
        return False
    res = lldb.SBCommandReturnObject()
    lldb_obj.debugger.GetCommandInterpreter().HandleCommand("memstats", res)
    result = res.GetOutput()
    if result.split(":")[1].strip().find('None') == -1 :
        return True
    else:
        return False

# EndMacro: memstats

# Macro: showpgz

@lldb_command('showpgz', "A", fancy=True)
def PGZSummary(cmd_args=None, cmd_options={}, O=None):
    """ Routine to show all live PGZ allocations
        Usage: showpgz [-A]

        -A     show freed entries too
    """
    bt = uses = slots = 0
    try:
        slots  = unsigned(kern.GetGlobalVariable('pgz_slots'))
        uses   = unsigned(kern.GetGlobalVariable('pgz_uses'))
        pgzbt  = unsigned(kern.GetGlobalVariable('pgz_backtraces'))
        guards = unsigned(kern.GetGlobalVariable('zone_guard_pages'))
    except:
        pass
    if uses == 0:
        print("PGZ disabled")
        return

    if pgzbt == 0:
        print("PGZ not initialized yet")

    zi = kern.GetGlobalVariable('zone_info')
    page_size = unsigned(kern.globals.page_size)
    pgz_min = unsigned(zi.zi_pgz_range.min_address) + page_size
    pgz_max = unsigned(zi.zi_pgz_range.max_address)

    target = LazyTarget.GetTarget()
    whatis = kmemory.WhatisProvider.get_shared()

    for i, addr in enumerate(range(pgz_min, pgz_max, 2 * page_size)):
        mo = whatis.find_provider(addr).lookup(addr)

        if not mo.real_addr:
            continue

        live = mo.status == 'allocated'

        if not live and "-A" not in cmd_options:
            continue

        with O.table("Element {:4d}: {:<#20x} ({:<s})".format(i, mo.elem_addr, mo.zone.name)):
            print("PGZ Allocation backtrace:")
            for pc in mo.meta.pgz_alloc_bt_frames:
                print(" " + GetSourceInformationForAddress(pc))

            if not live:
                print("PGZ Free backtrace:")
                for pc in mo.meta.pgz_free_bt_frames:
                    print(" " + GetSourceInformationForAddress(pc))

    avail = kern.GetGlobalVariable("pgz_slot_avail")
    quarantine = kern.GetGlobalVariable("pgz_quarantine")

    print("{:<20s}: {:<d}".format("slots", slots))
    print("{:<20s}: {:<d}".format("slots_used", slots - avail - quarantine))
    print("{:<20s}: {:<d}".format("slots_avail", avail))
    print("{:<20s}: {:<d}".format("quarantine", quarantine))
    print("{:<20s}: {:<d}".format("sampling", kern.GetGlobalVariable("pgz_sample_rate")))
    print("{:<20s}: {:<d}".format("guard pages", guards))

# EndMacro: showpgz

@lldb_command('whatis')
def WhatIsHelper(cmd_args=None):
    """ Routine to show information about a kernel pointer
        Usage: whatis <address>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")

    address  = kmemory.KMem.get_shared().make_address(ArgumentStringToInt(cmd_args[0]))
    provider = kmemory.WhatisProvider.get_shared().find_provider(address)
    mo       = provider.lookup(address)
    provider.describe(mo)
    mo.describe(verbose = True)

# Macro: showzcache

@lldb_type_summary(['zone','zone_t'])
@header("{:18s}  {:32s}  {:>8s}  {:>6s}  {:>6s}  {:>6s}  {:>6s}  {:>6s}   {:>7s}  {:<s}".format(
    'ZONE', 'NAME', 'CONT', 'USED', 'CACHED', 'RECIRC', 'FREE', 'FAIL', 'DEPOT', 'CPU_CACHES'))
def GetZoneCacheCPUSummary(zone, zone_security, O):
    """ Summarize a zone's cache broken up per cpu
        params:
          zone: value - obj representing a zone in kernel
        returns:
          str - summary of the zone's per CPU cache contents
    """
    format_string  = '{zone:#018x}  {:32s}  {cont:8.2f}  '
    format_string += '{used:6d}  {cached:6d}  {recirc:6d}  {free:6d}  {fail:6d}   '
    format_string += '{zone.z_depot_size:3d}/{zone.z_depot_limit:3d}  {cpuinfo:s}'
    cache_elem_count = 0

    mag_capacity = unsigned(kern.GetGlobalVariable('_zc_mag_size'))

    recirc_elem_count = zone.z_recirc.zd_full * mag_capacity
    free_elem_count = zone.z_elems_free + recirc_elem_count
    cpu_info = ""

    if zone.z_pcpu_cache:
        depot_cur = 0
        depot_full = 0
        depot_empty = 0
        for cache in IterateZPerCPU(zone.z_pcpu_cache):
            depot_cur += unsigned(cache.zc_alloc_cur)
            depot_cur += unsigned(cache.zc_free_cur)
            depot_full += unsigned(cache.zc_depot.zd_full)
            depot_empty += unsigned(cache.zc_depot.zd_empty)
        cache_elem_count += depot_cur + depot_full * mag_capacity

        cpus = unsigned(kern.globals.zpercpu_early_count)
        cpu_info = "total: {:d}, avg: {:.1f}, full: {:d}, emtpy: {:d}".format(
                depot_cur, float(depot_cur) / cpus, depot_full, depot_empty)

    fail = 0
    for stats in IterateZPerCPU(zone.z_stats):
        fail += unsigned(stats.zs_alloc_fail)

    print(O.format(format_string, ZoneName(zone, zone_security),
            cached=cache_elem_count, free=free_elem_count,
            used=zone.z_elems_avail - cache_elem_count - free_elem_count,
            min_wma = (zone.z_elems_free_wma - zone.z_recirc_full_wma * mag_capacity) // 256,
            cont=float(zone.z_recirc_cont_wma) / 256.,
            fail=fail, recirc=recirc_elem_count,
            zone=zone, cpuinfo = cpu_info))

@lldb_command('showzcache', fancy=True)
def ZcacheCPUPrint(cmd_args=None, cmd_options={}, O=None):
    """
    Routine to print a summary listing of all the kernel zones cache contents

    Usage: showzcache [-V]

    Use -V       to see more detailed output
    """
    global kern
    with O.table(GetZoneCacheCPUSummary.header):
        if len(cmd_args) == 1:
            zone = kern.GetValueFromAddress(cmd_args[0], 'struct zone *')
            zone_array = [z[0] for z in kern.zones]
            zid = zone_array.index(zone)
            zone_security = kern.zones[zid][1]
            GetZoneCacheCPUSummary(zone, zone_security, O);
        else:
            for zval, zsval in kern.zones:
                if zval.z_self:
                    GetZoneCacheCPUSummary(zval, zsval, O)

# EndMacro: showzcache

def kalloc_array_decode(addr, elt_type):
    pac_shift = unsigned(kern.globals.kalloc_array_type_shift)
    page_size = kern.globals.page_size

    size      = None
    ptr       = None

    if pac_shift:
        addr = unsigned(addr)
        z_mask = 1 << pac_shift
        if addr & z_mask:
            size = ((addr & 0x10) + 32) << (addr & 0xf)
            ptr  = addr & ~0x1f
        else:
            size = (addr & (page_size - 1)) * page_size
            ptr  = addr & -page_size
            if ptr: ptr |= z_mask
    else:
        KALLOC_ARRAY_TYPE_BIT = 47
        KALLOC_ARRAY_PTR_FIX  = 0xffff800000000000 # ~0ul << 47
        # do not cast to an address, otherwise lldb/lldbwrap will sign-extend
        # and erase the top bits that have meaning, and sadness ensues
        addr = addr.GetSBValue().GetValueAsUnsigned()
        size = addr >> (KALLOC_ARRAY_TYPE_BIT + 1)
        if (addr & (1 << KALLOC_ARRAY_TYPE_BIT)):
            size *= page_size
        ptr = addr | KALLOC_ARRAY_PTR_FIX

    if isinstance(elt_type, str):
        elt_type = gettype(elt_type)

    target = LazyTarget.GetTarget()
    ptr    = target.xCreateValueFromAddress(None, ptr, elt_type)
    return (value(ptr.AddressOf()), size // elt_type.GetByteSize())

# Macro: zprint

def GetZone(zone_val, zs_val, marks, security_marks):
    """ Internal function which gets a phython dictionary containing important zone information.
        params:
          zone_val: value - obj representing a zone in kernel
        returns:
          zone - python dictionary with zone stats
    """
    pcpu_scale = 1
    if zone_val.z_percpu:
        pcpu_scale = unsigned(kern.globals.zpercpu_early_count)
    pagesize = kern.globals.page_size
    zone = {}
    mag_capacity = unsigned(kern.GetGlobalVariable('_zc_mag_size'))
    zone["page_count"] = unsigned(zone_val.z_wired_cur) * pcpu_scale
    zone["allfree_page_count"] = unsigned(zone_val.z_wired_empty)

    cache_elem_count = 0
    free_elem_count = zone_val.z_elems_free + zone_val.z_recirc.zd_full * mag_capacity

    if zone_val.z_pcpu_cache:
        for cache in IterateZPerCPU(zone_val.z_pcpu_cache):
            cache_elem_count += unsigned(cache.zc_alloc_cur)
            cache_elem_count += unsigned(cache.zc_free_cur)
            cache_elem_count += unsigned(cache.zc_depot.zd_full) * mag_capacity

    alloc_fail_count = 0
    for stats in IterateZPerCPU(zone_val.z_stats):
        alloc_fail_count += unsigned(stats.zs_alloc_fail)
    zone["alloc_fail_count"] = alloc_fail_count

    zone["size"] = zone["page_count"] * pagesize
    zone["submap_idx"] = unsigned(zs_val.z_submap_idx)

    zone["free_size"] = free_elem_count * zone_val.z_elem_size * pcpu_scale
    zone["cached_size"] = cache_elem_count * zone_val.z_elem_size * pcpu_scale
    zone["used_size"] = zone["size"] - zone["free_size"] - zone["cached_size"]

    zone["element_count"] = zone_val.z_elems_avail - zone_val.z_elems_free - cache_elem_count
    zone["cache_element_count"] = cache_elem_count
    zone["free_element_count"] = free_elem_count

    if zone_val.z_percpu:
        zone["allocation_size"] = unsigned(pagesize)
        zone["allocation_ncpu"] = unsigned(zone_val.z_chunk_pages)
    else:
        zone["allocation_size"] = unsigned(zone_val.z_chunk_pages * pagesize)
        zone["allocation_ncpu"] = 1
    zone["allocation_count"] = unsigned(zone["allocation_size"]) // unsigned(zone_val.z_elem_size)
    zone["allocation_waste"] = (zone["allocation_size"] % zone_val.z_elem_size) * zone["allocation_ncpu"]

    zone["destroyed"] = bool(getattr(zone_val, 'z_self', None))

    for mark, _ in marks:
        if mark == "exhaustible":
            zone[mark] = int(zone_val.z_wired_max) != 0xffffffff
        else:
            zone[mark] = bool(getattr(zone_val, mark, None))

    for mark, _ in security_marks:
        zone[mark] = bool(getattr(zone_val, mark, None))

    zone["name"] = ZoneName(zone_val, zs_val)

    zone["sequester_page_count"] = (unsigned(zone_val.z_va_cur) -
            unsigned(zone_val.z_wired_cur)) * pcpu_scale
    zone["page_count_max"] = unsigned(zone_val.z_wired_max) * pcpu_scale

    # Ensure the zone is serializable
    json.dumps(zone)
    return zone


@lldb_type_summary(['zone','zone_t'])
@header(("{:<18s}  {:_^47s}  {:_^24s}  {:_^13s}  {:_^28s}\n"+
"{:<18s}  {:>11s} {:>11s} {:>11s} {:>11s}  {:>8s} {:>7s} {:>7s}  {:>6s} {:>6s}  {:>8s} {:>6s} {:>5s} {:>7s}   {:<22s} {:<20s}").format(
'', 'SIZE (bytes)', 'ELEMENTS (#)', 'PAGES', 'ALLOC CHUNK CONFIG',
'ZONE', 'TOTAL', 'ALLOC', 'CACHE', 'FREE', 'ALLOC', 'CACHE', 'FREE', 'COUNT', 'FREE', 'SIZE (P)', 'ELTS', 'WASTE', 'ELT_SZ', 'FLAGS', 'NAME'))
def GetZoneSummary(zone_val, zs_val, marks, security_marks, stats):
    """ Summarize a zone with important information. See help zprint for description of each field
        params:
          zone_val: value - obj representing a zone in kernel
        returns:
          str - summary of the zone
    """
    pagesize = kern.globals.page_size
    out_string = ""
    zone = GetZone(zone_val, zs_val, marks, security_marks)

    pcpu_scale = 1
    if zone_val.z_percpu:
        pcpu_scale = unsigned(kern.globals.zpercpu_early_count)

    format_string  = '{zone:#018x}  {zd[size]:11,d} {zd[used_size]:11,d} {zd[cached_size]:11,d} {zd[free_size]:11,d}  '
    format_string += '{zd[element_count]:8,d} {zd[cache_element_count]:7,d} {zd[free_element_count]:7,d}  '
    format_string += '{z_wired_cur:6,d} {z_wired_empty:6,d}  '
    format_string += '{alloc_size_kb:3,d}K ({zone.z_chunk_pages:d}) '
    format_string += '{zd[allocation_count]:6,d} {zd[allocation_waste]:5,d} {z_elem_size:7,d}   '
    format_string += '{markings:<22s} {zone_name:<20s}'

    markings = ""
    markings += "I" if zone["destroyed"] else " "

    for mark, sigil in marks:
        if mark == "exhaustible":
            markings += sigil if int(zone_val.z_wired_max) != 0xffffffff else " "
        else:
            markings += sigil if getattr(zone_val, mark, None) else " "
    for mark, sigil in security_marks:
        markings += sigil if getattr(zone_val, mark, None) else " "

    """ Z_SUBMAP_IDX_READ_ONLY == 1
    """
    markings += "%" if zone["submap_idx"] == 1 else " "

    alloc_size_kb = zone["allocation_size"] // 1024
    out_string += format_string.format(zone=zone_val, zd=zone,
            z_wired_cur=unsigned(zone_val.z_wired_cur) * pcpu_scale,
            z_wired_empty=unsigned(zone_val.z_wired_empty) * pcpu_scale,
            z_elem_size=unsigned(zone_val.z_elem_size) * pcpu_scale,
            alloc_size_kb=alloc_size_kb, markings=markings, zone_name=zone["name"])

    if zone["exhaustible"] :
            out_string += " (max: {:d})".format(zone["page_count_max"] * pagesize)

    if zone["sequester_page_count"] != 0 :
            out_string += " (sequester: {:d})".format(zone["sequester_page_count"])

    stats["cur_size"] += zone["size"]
    stats["used_size"] += zone["used_size"]
    stats["cached_size"] += zone["cached_size"]
    stats["free_size"] += zone["free_size"]
    stats["cur_pages"] += zone["page_count"]
    stats["free_pages"] += zone["allfree_page_count"]
    stats["seq_pages"] += zone["sequester_page_count"]

    return out_string

@lldb_command('zprint', "J", fancy=True)
def Zprint(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print a summary listing of all the kernel zones
        usage: zprint -J
                Output json
    All columns are printed in decimal
    Legend:
        $ - not encrypted during hibernation
        % - zone is a read-only zone
        A - currently trying to allocate more backing memory from kmem_alloc without VM priv
        C - collectable
        D - destructible
        E - Per-cpu caching is enabled for this zone
        G - currently running GC
        H - exhaustible
        I - zone was destroyed and is no longer valid
        L - zone is being logged
        O - does not allow refill callout to fill zone on noblock allocation
        R - will be refilled when below low water mark
        L - zone is LIFO
    """
    global kern

    marks = [
            ["collectable",          "C"],
            ["z_destructible",       "D"],
            ["exhaustible",          "H"],
            ["z_elems_rsv",          "R"],
            ["no_callout",           "O"],
            ["z_btlog",              "L"],
            ["z_expander",           "A"],
            ["z_pcpu_cache",         "E"],
    ]
    security_marks = [
            ["z_noencrypt",          "$"],
            ["z_lifo",               "L"],
    ]

    stats = {
        "cur_size": 0, "used_size": 0, "cached_size": 0, "free_size": 0,
        "cur_pages": 0, "free_pages": 0, "seq_pages": 0
    }

    print_json = False
    if "-J" in cmd_options:
        print_json = True

    if print_json:
        zones = []
        for zval, zsval in kern.zones:
            if zval.z_self:
                zones.append(GetZone(zval, zsval, marks, security_marks))

        print(json.dumps(zones))
    else:
        with O.table(GetZoneSummary.header):
            for zval, zsval in kern.zones:
                if zval.z_self:
                    print(GetZoneSummary(zval, zsval, marks, security_marks, stats))

            format_string  = '{VT.Bold}{name:19s} {stats[cur_size]:11,d} {stats[used_size]:11,d} {stats[cached_size]:11,d} {stats[free_size]:11,d} '
            format_string += '                           '
            format_string += '{stats[cur_pages]:6,d} {stats[free_pages]:6,d}{VT.EndBold}  '
            format_string += '(sequester: {VT.Bold}{stats[seq_pages]:,d}{VT.EndBold})'
            print(O.format(format_string, name="TOTALS", filler="", stats=stats))


@xnudebug_test('test_zprint')
def TestZprint(kernel_target, config, lldb_obj, isConnected ):
    """ Test the functionality of zprint command
        returns
         - False on failure
         - True on success
    """
    if not isConnected:
        print("Target is not connected. Cannot test memstats")
        return False
    res = lldb.SBCommandReturnObject()
    lldb_obj.debugger.GetCommandInterpreter().HandleCommand("zprint", res)
    result = res.GetOutput()
    if len(result.split("\n")) > 2:
        return True
    else:
        return False


# EndMacro: zprint
# Macro: showtypes
def GetBelongingKext(addr):
    try:
        kernel_range_start = kern.GetGlobalVariable('segDATACONSTB')
        kernel_range_end = kernel_range_start + kern.GetGlobalVariable(
            'segSizeDATACONST')
    except:
        kernel_range_start = kern.GetGlobalVariable('sconst')
        kernel_range_end = kernel_range_start + kern.GetGlobalVariable(
            'segSizeConst')
    if addr >= kernel_range_start and addr <= kernel_range_end:
        kext_name = "__kernel__"
    else:
        kext_name = FindKmodNameForAddr(addr)
    if kext_name is None:
        kext_name = "<not loaded>"
    return kext_name

def GetHeapIDForView(ktv):
    kalloc_type_heap_array = kern.GetGlobalVariable('kalloc_type_heap_array')
    kt_var_heaps = kern.GetGlobalVariable('kt_var_heaps') + 1
    heap_id = 0
    for i in range(kt_var_heaps):
        heap = kalloc_type_heap_array[i]
        ktv_start = cast(heap.kt_views, "struct kalloc_type_var_view *")
        if ktv_start.kt_heap_start == ktv.kt_heap_start:
            heap_id = i
            break
    return heap_id

def PrintVarHdr():
    print('    {0: <24s} {1: <40s} {2: <50s} {3: <20s} {4: <20s}'.format(
        "kalloc_type_var_view", "typename", "kext", "signature(hdr)",
        "signature(type)"))

def PrintVarType(ktv_cur, prev_types):
    typename = str(ktv_cur.kt_name)
    typename = typename.split("site.")[1]
    sig_hdr = str(ktv_cur.kt_sig_hdr)
    sig_type = str(ktv_cur.kt_sig_type)
    if typename not in prev_types or prev_types[typename] != [sig_hdr, sig_type]:
        print_sig = [sig_hdr, sig_type]
        if sig_type == "":
            print_sig = ["data-only", ""]
        print('    {0: <#24x} {1: <40s} {2: <50s} {3: <20s} {4: <20s}'
            .format(ktv_cur, typename, GetBelongingKext(ktv_cur),
            print_sig[0], print_sig[1]))
        prev_types[typename] = [sig_hdr, sig_type]

def PrintVarTypesPerHeap(idx):
    print("Heap: %d" % (idx))
    PrintVarHdr()
    kalloc_type_heap_array = kern.GetGlobalVariable('kalloc_type_heap_array')
    kt_var_heaps = kern.GetGlobalVariable('kt_var_heaps') + 1
    assert(idx < kt_var_heaps)
    heap = kalloc_type_heap_array[idx]
    ktv_cur = cast(heap.kt_views, "struct kalloc_type_var_view *")
    prev_types = {}
    while ktv_cur:
        PrintVarType(ktv_cur, prev_types)
        ktv_cur = cast(ktv_cur.kt_next, "struct kalloc_type_var_view *")

def ShowAllVarTypes():
    print("Variable kalloc type views")
    kt_var_heaps = kern.GetGlobalVariable('kt_var_heaps') + 1
    for i in range(kt_var_heaps):
        PrintVarTypesPerHeap(i)

def PrintFixedHdr():
    print('    {0: <24s} {1: <40s} {2: <50s} {3: <10s}'.format(
        "kalloc_type_view", "typename", "kext", "signature"))

def PrintFixedType(kt_cur, prev_types):
    typename = str(kt_cur.kt_zv.zv_name)
    if "site." in typename:
        typename = typename.split("site.")[1]
        sig = str(kt_cur.kt_signature)
    if typename not in prev_types or prev_types[typename] != sig:
        print_sig = sig
        if sig == "":
            print_sig = "data-only"
        print('    {0: <#24x} {1: <40s} {2: <50s} {3: <10s}'.format(
            kt_cur, typename, GetBelongingKext(kt_cur), print_sig))
        prev_types[typename] = sig

def PrintTypes(z):
    kt_cur = cast(z.z_views, "struct kalloc_type_view *")
    prev_types = {}
    PrintFixedHdr()
    while kt_cur:
        PrintFixedType(kt_cur, prev_types)
        kt_cur = cast(kt_cur.kt_zv.zv_next, "struct kalloc_type_view *")

def ShowTypesPerSize(size):
    kalloc_type_zarray = kern.GetGlobalVariable('kalloc_type_zarray')
    num_kt_sizeclass = kern.GetGlobalVariable('num_kt_sizeclass')
    for i in range(num_kt_sizeclass):
        zone = kalloc_type_zarray[i]
        if zone and zone.z_elem_size == size:
            while zone:
                print("Zone: %s (0x%x)" % (zone.z_name, zone))
                PrintTypes(zone)
                zone = zone.z_kt_next
            break

def ShowAllTypes():
    kalloc_type_zarray = kern.GetGlobalVariable('kalloc_type_zarray')
    num_kt_sizeclass = kern.GetGlobalVariable('num_kt_sizeclass')
    for i in range(num_kt_sizeclass):
        zone = kalloc_type_zarray[i]
        while zone:
            print("Zone: %s (0x%x)" % (zone.z_name, zone))
            PrintTypes(zone)
            zone = zone.z_kt_next

@lldb_command('showkalloctypes', 'Z:S:K:V')
def ShowKallocTypes(cmd_args=None, cmd_options={}):
    """
    prints kalloc types for a zone or sizeclass

    Usage: showkalloctypes [-Z <zone pointer or name>] [-S <sizeclass>] [-V]

    Use -Z       to show kalloc types associated to the specified zone name/ptr
    Use -S       to show all kalloc types of the specified sizeclass
    Use -K       to show the type and zone associated with a kalloc type view
    Use -V       to show all variable sized kalloc types

    If no options are provided kalloc types for all zones is printed.
    """
    if '-Z' in cmd_options:
        zone_arg = cmd_options['-Z']
        zone = GetZoneByName(zone_arg)
        if not zone:
            try:
                zone = kern.GetValueFromAddress(zone_arg, 'struct zone *')
            except:
                raise ArgumentError("Invalid zone {:s}".format(zone_arg))
        kalloc_type_var_str = "kalloc.type.var"
        zname = str(zone.z_name)
        if kalloc_type_var_str in zname:
            PrintVarTypesPerHeap(int(zname[len(kalloc_type_var_str)]))
            return
        print("Fixed size typed allocations for zone %s\n" % zname)
        PrintTypes(zone)
        zone_array = [z[0] for z in kern.zones]
        zid = zone_array.index(zone)
        zone_security = kern.zones[zid][1]
        if "data.kalloc." in ZoneName(zone, zone_security):
            # Print variable kalloc types that get redirected to data heap
            print("Variable sized typed allocations\n")
            PrintVarTypesPerHeap(0)
        return
    if '-S' in cmd_options:
        size = unsigned(cmd_options['-S'])
        if size == 0:
            raise ArgumentError("Invalid size {:s}".format(cmd_options['-S']))
        ShowTypesPerSize(size)
        return
    if '-K' in cmd_options:
        ktv_arg = cmd_options['-K']
        try:
            ktv = kern.GetValueFromAddress(ktv_arg, 'kalloc_type_view_t')
        except:
            raise ArgumentError("Invalid kalloc type view {:s}".format(ktv_arg))
        zone = ktv.kt_zv.zv_zone
        # Var views have version info in the first 16bits
        if zone & 0xf == 0:
            print("View is in zone %s\n" % zone.z_name)
            PrintFixedHdr()
            PrintFixedType(ktv, {})
        else:
            ktv = kern.GetValueFromAddress(ktv_arg, 'kalloc_type_var_view_t')
            heap_id = GetHeapIDForView(ktv)
            print("View is in heap %d\n" % heap_id)
            PrintVarHdr()
            PrintVarType(ktv, {})
        return

    if '-V' in cmd_options:
        ShowAllVarTypes()
        return
    ShowAllTypes()
    ShowAllVarTypes()

# EndMacro: showkalloctypes
# Macro: showzchunks

@header("{: <20s} {: <20s} {: <20s} {: <10s} {: <8s} {: <4s} {: >9s}".format(
    "Zone", "Metadata", "Page", "Kind", "Queue", "Pgs", "Allocs"))
def GetZoneChunk(zone, meta, queue, O=None):
    format_string  = "{zone.address: <#20x} "
    format_string += "{meta.address: <#20x} {meta.page_addr: <#20x} "
    format_string += "{kind:<10s} {queue:<8s} {pgs:<1d}/{chunk:<1d}  "
    format_string += "{alloc_count: >4d}/{avail_count: >4d}"

    alloc_count = avail_count = 0
    chunk       = zone.chunk_pages
    meta_sbv    = meta.mo_sbv

    if meta_sbv != meta.sbv:
        kind = "secondary"
        pgs  = zone.chunk_pages - meta_sbv.xGetIntegerByName('zm_page_index')
        if meta_sbv.xGetIntegerByName('zm_guarded'):
            format_string += " {VT.Green}guarded-after{VT.Default}"
    else:
        kind = "primary"
        pgs  = meta_sbv.xGetIntegerByName('zm_chunk_len')
        if pgs == 0:
            pgs = chunk

        prev_sbv = meta_sbv.xGetSiblingValueAtIndex(-1)
        if prev_sbv.xGetIntegerByName('zm_chunk_len') == GetEnumValue('zm_len_t', 'ZM_PGZ_GUARD'):
            if prev_sbv.xGetIntegerByName('zm_guarded'):
                format_string += " {VT.Green}lead-guard{VT.Default}"
            else:
                format_string += " {VT.Green}guarded-before{VT.Default}"

        if pgs == chunk and meta_sbv.xGetIntegerByName('zm_guarded'):
            format_string += " {VT.Green}guarded-after{VT.Default}"

        alloc_count = meta_sbv.xGetIntegerByName('zm_alloc_size') // zone.elem_outer_size
        avail_count = chunk * zone.kmem.page_size // zone.elem_outer_size

    return O.format(format_string, zone=zone, meta=meta,
            alloc_count=alloc_count, avail_count=avail_count,
            queue=queue, kind=kind, pgs=pgs, chunk=chunk)

def ShowZChunksImpl(zone, extra_addr=None, cmd_options={}, O=None):
    verbose = '-V' in cmd_options
    cached  = zone.cached()
    recirc  = zone.recirc()

    def do_content(meta, O, indent=False):
        with O.table("{:>5s}  {:<20s} {:<10s}".format("#", "Element", "State"), indent=indent):
            for i, e in enumerate(meta.iter_all(zone)):
                if not meta.is_allocated(zone, e):
                    status = "free"
                elif e in cached:
                    status = "cached"
                elif e in recirc:
                    status = "recirc"
                else:
                    status = "allocated"
                print(O.format("{:5d}  {:<#20x} {:10s}", i, e, status))

    if extra_addr is None:
        with O.table(GetZoneChunk.header):
            metas = (
                (name, meta)
                for name in ('full', 'partial', 'empty',)
                for meta in zone.iter_page_queue('z_pageq_' + name)
            )
            for name, meta in metas:
                print(GetZoneChunk(zone, meta, name, O))
                if verbose: do_content(meta, O, indent=True);
    else:
        whatis = kmemory.WhatisProvider.get_shared()
        mo     = whatis.find_provider(extra_addr).lookup(extra_addr)

        if zone.kmem.meta_range.contains(extra_addr):
            meta = mo
        else:
            meta = mo.meta

        with O.table(GetZoneChunk.header):
            print(GetZoneChunk(zone, meta, "N/A", O))
        do_content(meta, O)

@lldb_command('showzchunks', "IV", fancy=True)
def ShowZChunks(cmd_args=None, cmd_options={}, O=None):
    """
    prints the list of zone chunks, or the content of a given chunk

    Usage: showzchunks <zone> [-I] [-V] [address]

    Use -I       to interpret [address] as a page index
    Use -V       to show the contents of all the chunks

    [address]    can by any address belonging to the zone, or metadata
    """

    if cmd_args is None or len(cmd_args) == 0:
        return O.error('missing zone argument')

    zone = kmemory.Zone(ArgumentStringToInt(cmd_args[0]))

    if len(cmd_args) == 1:
        ShowZChunksImpl(zone, cmd_options=cmd_options, O=O)
    else:
        ShowZChunksImpl(zone, extra_addr=ArgumentStringToInt(cmd_args[1]), cmd_options=cmd_options, O=O)

@lldb_command('showallzchunks', fancy=True)
def ShowAllZChunks(cmd_args=None, cmd_options={}, O=None):
    """
    prints the list of all zone chunks

    Usage: showallzchunks
    """

    for zid in range(kmemory.KMem.get_shared().num_zones):
        z = kmemory.Zone(zid)
        if z.initialized:
            ShowZChunksImpl(z, O=O)

# EndMacro: showzchunks
# Macro: zstack stuff

ZSTACK_OPS = { 0: "free", 1: "alloc" }

@lldb_command('showbtref', "A", fancy=True)
def ShowBTRef(cmd_args=None, cmd_options={}, O=None):
    """ Show a backtrace ref

        usage: showbtref <ref...>
    """

    btl = kmemory.BTLibrary.get_shared()

    for arg in cmd_args:
        arg = ArgumentStringToInt(arg)
        btl.get_stack(arg).describe()

@lldb_command('_showbtlibrary', fancy=True)
def ShowBTLibrary(cmd_args=None, cmd_options={}, O=None):
    """ Dump the entire bt library (debugging tool for the bt library itself)

        usage: showbtlibrary
    """

    target = LazyTarget.GetTarget()
    kmem = kmemory.KMem.get_shared()
    btl = kmemory.BTLibrary.get_shared()
    btl_shift = btl.shift

    btl.describe()

    hdr = "{:<12s} {:<12s} {:<12s} {:>3s}  {:>5s}  {:<20s}".format(
        "btref", "hash", "next", "len", "ref", "stack")
    hdr2 = hdr + "  {:<20s}".format("smr seq")

    with O.table("{:<20s} {:>6s} {:>6s}".format("hash", "idx", "slot")):
        loop = (
            (i, arr, j, ref)
            for i, arr in enumerate(kmem.iter_addresses(target.xIterAsULong(
                btl.hash_address, btl.buckets
            )))
            for j, ref in enumerate(target.xIterAsUInt32(
                arr, kmemory.BTLibrary.BTL_HASH_COUNT
            ))
            if ref
        )

        for i, arr, j, ref in loop:
            print(O.format("{:#20x} {:6d} {:6d}", arr, i, j))

            with O.table(hdr, indent=True):
                while ref:
                    bts = btl.get_stack(ref)
                    err = ""
                    h   = bts.bts_hash
                    if (h & 0xff) != j:
                        err = O.format(" {VT.DarkRed}wrong slot{VT.Default}")
                    if (h >> (32 - btl_shift)) != i:
                        err += O.format(" {VT.DarkRed}wrong bucket{VT.Default}")

                    print(O.format(
                        "{0.bts_ref:#010x}   "
                        "{0.bts_hash:#010x}   "
                        "{0.bts_next:#010x}   "
                        "{0.bts_len:>3d}  "
                        "{0.refcount:>5d}  "
                        "{&v:<#20x}"
                        "{1:s}",
                        bts, err, v=bts.sbv
                    ))
                    ref = bts.bts_next

        print("freelist")
        with O.table(hdr2, indent=True):
            ref = btl.free_head
            while ref:
                bts = btl.get_stack(ref)
                print(O.format(
                    "{0.bts_ref:#010x}   "
                    "{0.bts_hash:#010x}   "
                    "{0.bts_next:#010x}   "
                    "{0.bts_len:>3d}  "
                    "{0.refcount:>5d}  "
                    "{&v:<#20x}  "
                    "{$v.bts_free_seq:#x}",
                    bts, v=bts.sbv
                ))
                ref = bts.next_free

@header("{:<20s} {:<6s} {:>9s}".format("btlog", "type", "count"))
@lldb_command('showbtlog', fancy=True)
def ShowBTLog(cmd_args=None, cmd_options={}, O=None):
    """ Display a summary of the specified btlog
        Usage: showbtlog <btlog address>
    """

    if cmd_args is None or len(cmd_args) == 0:
        return O.error('missing btlog address argument')

    btlib = kmemory.BTLibrary.get_shared()

    with O.table(ShowBTLog.header):
        btl = btlib.btlog_from_address(ArgumentStringToInt(cmd_args[0]))
        print(O.format("{0.address:<#20x} {0.btl_type:<6s} {0.btl_count:>9d}", btl))

@lldb_command('showbtlogrecords', 'B:E:C:FR', fancy=True)
def ShowBTLogRecords(cmd_args=None, cmd_options={}, O=None):
    """ Print all records in the btlog from head to tail.

        Usage: showbtlogrecords <btlog addr> [-B <btref>] [-E <addr>] [-F]

            -B <btref>      limit output to elements with backtrace <ref>
            -E <addr>       limit output to elements with address <addr>
            -C <num>        number of elements to show
            -F              show full backtraces
            -R              reverse order
    """

    if cmd_args is None or len(cmd_args) == 0:
        return O.error('missing btlog argument')

    btref   = ArgumentStringToInt(cmd_options["-B"]) if "-B" in cmd_options else None
    element = ArgumentStringToInt(cmd_options["-E"]) if "-E" in cmd_options else None
    count   = int(cmd_options["-C"], 0) if "-C" in cmd_options else None
    reverse = "-R" in cmd_options

    btlib = kmemory.BTLibrary.get_shared()
    btlog = btlib.btlog_from_address(ArgumentStringToInt(cmd_args[0]))

    with O.table("{:<10s}  {:<20s} {:>3s}  {:<10s}".format("idx", "element", "OP", "backtrace")):
        for i, record in enumerate(btlog.iter_records(
            wantElement=element, wantBtref=btref, reverse=reverse
        )):
            print(O.format("{0.index:<10d}  {0.address:<#20x} {0.op:>3d}  {0.ref:#010x}", record))
            if "-F" in cmd_options:
                print(*btlib.get_stack(record.ref).symbolicated_frames(prefix="    "), sep="\n")
            if count and i >= count:
                break

@lldb_command('zstack_showzonesbeinglogged', fancy=True)
def ZstackShowZonesBeingLogged(cmd_args=None, cmd_options={}, O=None):
    """ Show all zones which have BTLog enabled.
    """
    global kern

    with O.table("{:<20s} {:<20s} {:<6s} {:s}".format("zone", "btlog", "type", "name")):
        for zval, zsval in kern.zones:
            btlog = getattr(zval, 'z_btlog', None)
            if not btlog: continue
            btlog = kmemory.BTLog(btlog.GetSBValue())
            print(O.format("{0:<#20x} {1.address:<#20x} {1.btl_type:<6s} {2:s}",
                zval, btlog, ZoneName(zval, zsval)))

@header("{:<8s} {:10s} {:>10s}".format("op", "btref", "count"))
def ZStackShowIndexEntries(O, btlib, btidx):
    """
    Helper function to show BTLog index() entries
    """

    with O.table(ZStackShowIndexEntries.header):
        for ref, op, count in btidx:
            print(O.format("{:<8s} {:#010x} {:10d}", ZSTACK_OPS[op], ref, count))
            print(*btlib.get_stack(ref).symbolicated_frames(prefix="    "), sep="\n")

@lldb_command('zstack', fancy=True)
def Zstack(cmd_args=None, cmd_options={}, O=None):
    """ Zone leak debugging: Print the stack trace logged at <index> in the stacks list.

        Usage: zstack <btlog addr> <index> [<count>]

        If a <count> is supplied, it prints <count> stacks starting at <index>.

        The suggested usage is to look at stacks with high percentage of refs (maybe > 25%).
        The stack trace that occurs the most is probably the cause of the leak. Use zstack_findleak for that.
    """

    if cmd_args is None or len(cmd_args) == 0:
        return O.error('missing btlog argument')

    btlib = kmemory.BTLibrary.get_shared()
    btlog = btlib.btlog_from_address(ArgumentStringToInt(cmd_args[0]))
    btidx = sorted(btlog.index())

    ZStackShowIndexEntries(O, btlib, btidx)

@lldb_command('zstack_inorder', fancy=True)
def ZStackObsolete(cmd_args=None, cmd_options={}, O=None):
    """
    *** Obsolte macro ***
    """
    return O.error("Obsolete macro")

@lldb_command('zstack_findleak', fancy=True)
def zstack_findleak(cmd_args=None, cmd_options={}, O=None):
    """ Zone leak debugging: search the log and print the stack with the most active entries.

        Usage: zstack_findleak <btlog addr> [<count>]

        This is useful for verifying a suspected stack as being the source of
        the leak.
    """

    if cmd_args is None or len(cmd_args) == 0:
        return O.error('missing btlog argument')

    count = 1
    if len(cmd_args) > 1:
        count = int(cmd_args[1])

    btlib = kmemory.BTLibrary.get_shared()
    btlog = btlib.btlog_from_address(ArgumentStringToInt(cmd_args[0]))
    if not btlog.is_hash():
        return O.error('btlog is not a hash')

    btidx = sorted(btlog.index(), key=itemgetter(2), reverse=True)
    ZStackShowIndexEntries(O, btlib, btidx[:count])

@header("{:<8s} {:10s}".format("op", "btref"))
@lldb_command('zstack_findelem', fancy=True)
def ZStackFindElem(cmd_args=None, cmd_options={}, O=None):
    """ Zone corruption debugging: search the zone log and print out the stack traces for all log entries that
        refer to the given zone element.

        Usage: zstack_findelem <btlog addr> <elem addr>

        When the kernel panics due to a corrupted zone element,
        get the element address and use this command.

        This will show you the stack traces of all logged zalloc and zfree
        operations which tells you who touched the element in the recent past.

        This also makes double-frees readily apparent.
    """

    if len(cmd_args) < 2:
        return O.error('missing btlog or element argument')

    btlib = kmemory.BTLibrary.get_shared()
    btlog = btlib.btlog_from_address(ArgumentStringToInt(cmd_args[0]))
    addr  = ArgumentStringToInt(cmd_args[1])
    prev_op = None

    with O.table(ZStackFindElem.header):
        for _, _, op, ref in btlog.iter_records(wantElement=addr):
            print(O.format("{:<8s} {:#010x}", ZSTACK_OPS[op], ref))
            print(*btlib.get_stack(ref).symbolicated_frames(prefix="    "), sep="\n")
            if prev_op == op:
                print("")
                O.error("******** double {:s} ********", ZSTACK_OPS[op])
                print("")
            prev_op = op

@lldb_command('zstack_findtop', 'N:', fancy=True)
def ShowZstackTop(cmd_args=None, cmd_options={}, O=None):
    """ Zone leak debugging: search the log and print the stacks with the most active references
        in the stack trace.

        Usage: zstack_findtop [-N <n-stacks>] <btlog-addr>
    """

    if cmd_args is None or len(cmd_args) == 0:
        return O.error('missing btlog argument')

    count = int(cmd_options.get("-N", 5))
    btlib = kmemory.BTLibrary.get_shared()
    btlog = btlib.btlog_from_address(ArgumentStringToInt(cmd_args[0]))
    btidx = sorted(btlog.index(), key=itemgetter(2), reverse=True)

    ZStackShowIndexEntries(O, btlib, btidx[:count])

# EndMacro: zstack stuff
#Macro: showpcpu

@lldb_command('showpcpu', "N:V", fancy=True)
def ShowPCPU(cmd_args=None, cmd_options={}, O=None):
    """ Show per-cpu variables
    usage: showpcpu [-N <cpu>] [-V] <variable name>

    Use -N <cpu> to only dump the value for a given CPU number
    Use -V       to dump the values of the variables after their addresses
    """

    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")

    cpu = int(cmd_options["-N"], 0) if "-N" in cmd_options else None
    var = kmemory.PERCPUValue(cmd_args[0])
    fmt = "{VT.Bold}CPU {cpu:2d}{VT.Reset} ({type} *){addr:#x}"

    if "-V" in cmd_options:
        fmt = "{VT.Bold}CPU {cpu:2d} ({type} *){addr:#x}{VT.Reset} {v!s}\n"

    if cpu is not None:
        try:
            v = var[cpu]
        except IndexError:
            raise ArgumentError("Invalid cpu {}".format(cpu))
        print(O.format(fmt, cpu=cpu, type=v.GetType().GetDisplayTypeName(), addr=v.GetLoadAddress(), v=v))
    else:
        for cpu, v in var.items():
            print(O.format(fmt, cpu=cpu, type=v.GetType().GetDisplayTypeName(), addr=v.GetLoadAddress(), v=v))

#EndMacro: showpcpu
# Macro: showioalloc

@lldb_command('showioalloc')
def ShowIOAllocations(cmd_args=None):
    """ Show some accounting of memory allocated by IOKit allocators. See ioalloccount man page for details.
        Routine to display a summary of memory accounting allocated by IOKit allocators.
    """
    print("Instance allocation  = {0: <#0x} = {1: d}K".format(kern.globals.debug_ivars_size, kern.globals.debug_ivars_size // 1024))
    print("Container allocation = {0: <#0x} = {1: d}K".format(kern.globals.debug_container_malloc_size, kern.globals.debug_container_malloc_size // 1024))
    print("IOMalloc allocation  = {0: <#0x} = {1: d}K".format(kern.globals.debug_iomalloc_size, kern.globals.debug_iomalloc_size // 1024))
    print("Pageable allocation  = {0: <#0x} = {1: d}K".format(kern.globals.debug_iomallocpageable_size, kern.globals.debug_iomallocpageable_size // 1024))

# EndMacro: showioalloc
# Macro: showselectmem

@lldb_command('showselectmem', "S:")
def ShowSelectMem(cmd_args=None, cmd_options={}):
    """ Show memory cached by threads on calls to select.

        usage: showselectmem [-v]
            -v        : print each thread's memory
                        (one line per thread with non-zero select memory)
            -S {addr} : Find the thread whose thread-local select set
                        matches the given address
    """
    verbose = False
    opt_wqs = 0
    if config['verbosity'] > vHUMAN:
        verbose = True
    if "-S" in cmd_options:
        opt_wqs = unsigned(kern.GetValueFromAddress(cmd_options["-S"], 'uint64_t *'))
        if opt_wqs == 0:
            raise ArgumentError("Invalid waitq set address: {:s}".format(cmd_options["-S"]))
    selmem = 0
    if verbose:
        print("{:18s} {:10s} {:s}".format('Task', 'Thread ID', 'Select Mem (bytes)'))
    for t in kern.tasks:
        for th in IterateQueue(t.threads, 'thread *', 'task_threads'):
            uth = GetBSDThread(th)
            wqs = 0
            if hasattr(uth, 'uu_allocsize'): # old style
                thmem = uth.uu_allocsize
                wqs = uth.uu_wqset
            elif hasattr(uth, 'uu_wqstate_sz'): # new style
                thmem = uth.uu_wqstate_sz
                wqs = uth.uu_wqset
            else:
                print("What kind of uthread is this?!")
                return
            if opt_wqs and opt_wqs == unsigned(wqs):
                print("FOUND: {:#x} in thread: {:#x} ({:#x})".format(opt_wqs, unsigned(th), unsigned(th.thread_id)))
            if verbose and thmem > 0:
                print("{:<#18x} {:<#10x} {:d}".format(unsigned(t), unsigned(th.thread_id), thmem))
            selmem += thmem
    print('-'*40)
    print("Total: {:d} bytes ({:d} kbytes)".format(selmem, selmem // 1024))

# Endmacro: showselectmem

# Macro: showtaskvme
@lldb_command('showtaskvme', "PS")
def ShowTaskVmeHelper(cmd_args=None, cmd_options={}):
    """ Display a summary list of the specified vm_map's entries
        Usage: showtaskvme <task address>  (ex. showtaskvme 0x00ataskptr00 )
        Use -S flag to show VM object shadow chains
        Use -P flag to show pager info (mapped file, compressed pages, ...)
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    show_pager_info = False
    show_all_shadows = False
    if "-P" in cmd_options:
        show_pager_info = True
    if "-S" in cmd_options:
        show_all_shadows = True
    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    ShowTaskVMEntries(task, show_pager_info, show_all_shadows)

@lldb_command('showallvme', "PS")
def ShowAllVME(cmd_args=None, cmd_options={}):
    """ Routine to print a summary listing of all the vm map entries
        Go Through each task in system and show the vm memory regions
        Use -S flag to show VM object shadow chains
        Use -P flag to show pager info (mapped file, compressed pages, ...)
    """
    show_pager_info = False
    show_all_shadows = False
    if "-P" in cmd_options:
        show_pager_info = True
    if "-S" in cmd_options:
        show_all_shadows = True
    for task in kern.tasks:
        ShowTaskVMEntries(task, show_pager_info, show_all_shadows)

@lldb_command('showallvmobjects', 'S:PAIEH:')
def ShowAllVMObjects(cmd_args=None, cmd_options={}):
    """
    Show all vm objects.
    Optional Arguments:
        -S <virtual,resident,wired,compressed>
            sort by (default descending) the given field
            'compressed' implies -I
        -P
            show pager information
        -A
            sort in ascending order
        -I
            show only internal objects
        -E
            show only external objects
        -H <N>
            show only the first N objects
    """
    if '-S' in cmd_options:
        sort_by = cmd_options['-S'].lower()
        if sort_by not in {'wired', 'resident', 'virtual', 'compressed'}:
            print(f'error: Unrecognized sorting field \'{sort_by}\'')
            return
    else:
        sort_by = None
    show_pager_info = '-P' in cmd_options
    internal_only = '-I' in cmd_options
    external_only = '-E' in cmd_options
    if external_only and internal_only:
        print('error: Only one of -E and -I may be provided')
        return
    if '-H' in cmd_options:
        head = int(cmd_options['-H'])
    else:
        head = None

    all_objects = []
    i = 0
    for _vmo in kmemory.Zone("vm objects").iter_allocated(gettype('struct vm_object')):
        if not sort_by and head and i >= head:
            break
        vmo = value(_vmo.AddressOf())
        if vmo.ref_count == 0:
            continue
        if internal_only and vmo.internal == 0:
            continue
        if external_only and vmo.internal == 1:
            continue
        if sort_by is not None:
            if sort_by == 'resident':
                val = vmo.resident_page_count
            elif sort_by == 'wired':
                val = vmo.wired_page_count
            elif sort_by == 'virtual':
                if vmo.internal:
                    val = vmo.vo_un1.vou_size
                else:
                    val = -1
            elif sort_by == 'compressed':
                if vmo.internal == 0:
                    continue
                if vmo.pager == 0:
                    val = 0
                    continue
                val = GetCompressedPagesForObject(vmo)
            all_objects.append((vmo, val))
        else:
            showvmobject(vmo, show_pager_info=show_pager_info)
        i += 1

    if sort_by:
        descending = '-A' not in cmd_options
        i = 0
        for vmo, _ in sorted(all_objects, key=lambda o: o[1], reverse=descending):
            if head and i >= head:
                break
            showvmobject(vmo, show_pager_info=show_pager_info)
            i += 1

@lldb_command('showallvm')
def ShowAllVM(cmd_args=None):
    """ Routine to print a summary listing of all the vm maps
    """
    for task in kern.tasks:
        print(GetTaskSummary.header + ' ' + GetProcSummary.header)
        print(GetTaskSummary(task) + ' ' + GetProcSummary(GetProcFromTask(task)))
        print(GetVMMapSummary.header)
        print(GetVMMapSummary(task.map))

@lldb_command("showtaskvm")
def ShowTaskVM(cmd_args=None):
    """ Display info about the specified task's vm_map
        syntax: (lldb) showtaskvm <task_ptr>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not task:
        print("Unknown arguments.")
        return False
    print(GetTaskSummary.header + ' ' + GetProcSummary.header)
    print(GetTaskSummary(task) + ' ' + GetProcSummary(GetProcFromTask(task)))
    print(GetVMMapSummary.header)
    print(GetVMMapSummary(task.map))
    return True

def GetLedgerEntryBalance(template, ledger, idx):
    entry = GetLedgerEntryWithTemplate(template, ledger, idx)
    return entry['balance']

class VmStats(object):
    def __init__(self):
        self.wired_count = 0
        self.resident_count = 0
        self.new_resident_count = 0
        self.resident_max = 0
        self.internal = 0
        self.external = 0
        self.reusable = 0
        self.footprint = 0
        self.footprint_peak = 0
        self.compressed = 0
        self.compressed_peak = 0
        self.compressed_lifetime = 0

    @property
    def error(self):
        error = ''
        if self.internal < 0:
            error += '*'
        if self.external < 0:
            error += '*'
        if self.reusable < 0:
            error += '*'
        if self.footprint < 0:
            error += '*'
        if self.compressed < 0:
            error += '*'
        if self.compressed_peak < 0:
            error += '*'
        if self.compressed_lifetime < 0:
            error += '*'
        if self.new_resident_count +self.reusable != self.resident_count:
            error += '*'
        return error

    def __str__(self):
        entry_format = "{s.vmmap.hdr.nentries: >6d} {s.wired_count: >10d} {s.vsize: >10d} {s.resident_count: >10d} {s.new_resident_count: >10d} {s.resident_max: >10d} {s.internal: >10d} {s.external: >10d} {s.reusable: >10d} {s.footprint: >10d} {s.footprint_peak: >10d} {s.compressed: >10d} {s.compressed_peak: >10d} {s.compressed_lifetime: >10d} {s.pid: >10d} {s.proc_name: <32s} {s.error}"
        return entry_format.format(s=self)
    
    def __repr__(self):
        return self.__str__()

    def __add__(self, other):
        self.wired_count += other.wired_count
        self.resident_count += other.resident_count
        self.new_resident_count += other.new_resident_count
        self.resident_max += other.resident_max
        self.internal += other.internal
        self.external += other.external
        self.reusable += other.reusable
        self.footprint += other.footprint
        self.footprint_peak += other.footprint_peak
        self.compressed += other.compressed
        self.compressed_peak += other.compressed_peak
        self.compressed_lifetime += other.compressed_lifetime
        return self


@lldb_command('showallvmstats', 'S:A')
def ShowAllVMStats(cmd_args=None, cmd_options={}):
    """ Print a summary of vm statistics in a table format
        usage: showallvmstats

            A sorting option may be provided of <wired_count, resident_count, resident_max, internal, external, reusable, footprint, footprint_peak, compressed, compressed_peak, compressed_lifetime, new_resident_count, proc_name, pid, vsize>
            e.g. to sort by compressed memory use:
                showallvmstats -S compressed
            Default behavior is to sort in descending order.  To use ascending order, you may provide -A.
            e.g. to sort by pid in ascending order:
                showallvmstats -S pid -A
    """

    valid_sorting_options = ['wired_count', 'resident_count', 'resident_max', 'internal', \
                             'external', 'reusable', 'compressed', 'compressed_peak', \
                             'compressed_lifetime', 'new_resident_count', \
                             'proc_name', 'pid', 'vsize', 'footprint']

    if ('-S' in cmd_options) and (cmd_options['-S'] not in valid_sorting_options):
        raise ArgumentError('Invalid sorting key \'{}\' provided to -S'.format(cmd_options['-S']))
    sort_key =  cmd_options['-S'] if '-S' in cmd_options else None
    ascending_sort = False
    if '-A' in cmd_options:
        if sort_key is None:
            raise ArgumentError('A sorting key must be provided when specifying ascending sorting order')
        ascending_sort = True

    page_size = kern.globals.page_size

    hdr_format = "{:>6s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:<20s} {:1s}"
    print(hdr_format.format('#ents', 'wired', 'vsize', 'rsize', 'NEW RSIZE', 'max rsize', 'internal', 'external', 'reusable', 'footprint', 'footprint', 'compressed', 'compressed', 'compressed', 'pid', 'command', ''))
    print(hdr_format.format('', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(peak)', '(current)', '(peak)', '(lifetime)', '', '', ''))
    total_format = "{0: >6} {s.wired_count: >10d} {1: >10} {s.resident_count: >10d} {s.new_resident_count: >10d} {s.resident_max: >10d} {s.internal: >10d} {s.external: >10d} {s.reusable: >10d} {s.footprint: >10d} {s.footprint_peak: >10d} {s.compressed: >10d} {s.compressed_peak: >10d} {s.compressed_lifetime: >10d} {1: >10} {1: <32}"

    ledger_template = kern.globals.task_ledger_template
    entry_indices = {}
    entry_keys = ['wired_mem', 'phys_mem', 'internal', 'external', 'reusable', 'internal_compressed', 'phys_footprint']
    for key in entry_keys:
        entry_indices[key] = GetLedgerEntryIndex(ledger_template, key)
        assert(entry_indices[key] != -1)

    vmstats_totals = VmStats()
    vmstats_tasks = []
    for task in kern.tasks:
        vmstats = VmStats()
        proc = GetProcFromTask(task)
        vmmap = cast(task.map, '_vm_map *')
        page_size = 1 << int(vmmap.hdr.page_shift)
        task_ledgerp = task.ledger

        def GetLedgerEntryBalancePages(template, ledger, index):
            return GetLedgerEntryBalance(template, ledger, index) // page_size

        vmstats.wired_count = GetLedgerEntryBalancePages(ledger_template, task_ledgerp, entry_indices['wired_mem'])

        phys_mem_entry = GetLedgerEntryWithTemplate(ledger_template, task_ledgerp, entry_indices['phys_mem'])
        vmstats.resident_count = phys_mem_entry['balance'] // page_size
        vmstats.resident_max = phys_mem_entry['lifetime_max'] // page_size

        vmstats.internal = GetLedgerEntryBalancePages(ledger_template, task_ledgerp, entry_indices['internal'])
        vmstats.external = GetLedgerEntryBalancePages(ledger_template, task_ledgerp, entry_indices['external'])
        vmstats.reusable = GetLedgerEntryBalancePages(ledger_template, task_ledgerp, entry_indices['reusable'])

        phys_footprint_entry =  GetLedgerEntryWithTemplate(ledger_template, task_ledgerp, entry_indices['phys_footprint'])
        vmstats.footprint = phys_footprint_entry['balance'] // page_size
        vmstats.footprint_peak = phys_footprint_entry['lifetime_max'] // page_size

        internal_compressed_entry = GetLedgerEntryWithTemplate(ledger_template, task_ledgerp, entry_indices['internal_compressed'])
        vmstats.compressed = internal_compressed_entry['balance'] // page_size
        vmstats.compressed_peak = internal_compressed_entry['lifetime_max'] // page_size
        vmstats.compressed_lifetime = internal_compressed_entry['credit'] // page_size
        vmstats.new_resident_count = vmstats.internal + vmstats.external
        vmstats.proc = proc
        vmstats.proc_name = GetProcName(proc)
        vmstats.pid = GetProcPID(proc)
        vmstats.vmmap = vmmap
        vmstats.vsize = unsigned(vmmap.size) // page_size
        vmstats.task = task
        vmstats_totals += vmstats
        if sort_key:
            vmstats_tasks.append(vmstats)
        else:
            print(vmstats)

    if sort_key:
        vmstats_tasks.sort(key=lambda x: getattr(x, sort_key), reverse=not ascending_sort)
        for vmstats in vmstats_tasks:
            print(vmstats)
    print(total_format.format('TOTAL', '', s=vmstats_totals))


def ShowTaskVMEntries(task, show_pager_info, show_all_shadows):
    """  Routine to print out a summary listing of all the entries in a vm_map
        params:
            task - core.value : a object of type 'task *'
        returns:
            None
    """
    print("vm_map entries for task " + hex(task))
    print(GetTaskSummary.header)
    print(GetTaskSummary(task))
    if not task.map:
        print(f"Task {0: <#020x} has map = 0x0")
        return None
    print(GetVMMapSummary.header)
    print(GetVMMapSummary(task.map))
    vme_list_head = task.map.hdr.links
    vme_ptr_type = GetType('vm_map_entry *')
    print(GetVMEntrySummary.header)
    for vme in IterateQueue(vme_list_head, vme_ptr_type, "links"):
        print(GetVMEntrySummary(vme, show_pager_info, show_all_shadows))
    return None

@lldb_command("showmap")
def ShowMap(cmd_args=None):
    """ Routine to print out info about the specified vm_map
        usage: showmap <vm_map>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    map_val = kern.GetValueFromAddress(cmd_args[0], 'vm_map_t')
    print(GetVMMapSummary.header)
    print(GetVMMapSummary(map_val))

@lldb_command("showmapvme")
def ShowMapVME(cmd_args=None):
    """Routine to print out info about the specified vm_map and its vm entries
        usage: showmapvme <vm_map>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    map_val = kern.GetValueFromAddress(cmd_args[0], 'vm_map_t')
    print(GetVMMapSummary.header)
    print(GetVMMapSummary(map_val))
    vme_list_head = map_val.hdr.links
    vme_ptr_type = GetType('vm_map_entry *')
    print(GetVMEntrySummary.header)
    for vme in IterateQueue(vme_list_head, vme_ptr_type, "links"):
        print(GetVMEntrySummary(vme))
    return None

@lldb_command("showrangevme", "N:")
def ShowRangeVME(cmd_args=None, cmd_options={}):
    """Routine to print all vm map entries in the specified kmem range
       usage: showrangevme -N <kmem_range_id>
    """
    if '-N' in cmd_options:
        range_id = unsigned(cmd_options['-N'])
    else:
        raise ArgumentError("Range ID not specified")

    map = kern.globals.kernel_map
    range = kern.globals.kmem_ranges[range_id]
    start_vaddr = range.min_address
    end_vaddr = range.max_address
    showmapvme(map, start_vaddr, end_vaddr)
    return None

@lldb_command("showvmtagbtlog")
def ShowVmTagBtLog(cmd_args=None):
    """Routine to print vmtag backtracing corresponding to boot-arg "vmtaglog"
       usage: showvmtagbtlog
    """

    page_size = kern.globals.page_size
    map = kern.globals.kernel_map
    first_entry = map.hdr.links.next
    last_entry = map.hdr.links.prev
    entry = first_entry
    btrefs = []
    while entry != last_entry:
        if (entry.vme_kernel_object == 1) \
            and (entry.vme_tag_btref != 0) \
            and (entry.in_transition == 0):
            count = (entry.links.end - entry.links.start) // page_size
            btrefs.append((entry.vme_tag_btref, count))
        entry = entry.links.next

    btrefs.sort(key=itemgetter(1), reverse=True)
    btlib = kmemory.BTLibrary.get_shared()
    if btrefs:
        print('Found {} btrefs in the kernel object\n'.format(len(btrefs)))
    for ref, count in btrefs:
        print('{}'.format('*' * 80))
        print('btref: {:#08x}, count: {}\n'.format(ref, count))
        print(*btlib.get_stack(ref).symbolicated_frames(prefix="    "), sep="\n")
        print('')

    vmtaglog_btlog_address = int(kern.globals.vmtaglog_btlog)
    if vmtaglog_btlog_address != 0:
        print("btrefs from non-kernel object:\n")
        btlog = btlib.btlog_from_address(vmtaglog_btlog_address)
        btidx = sorted(btlog.index(), key=itemgetter(2), reverse=True)
        for ref, _, count in btidx:
            print('ref: {:#08x}, count: {}'.format(ref, count))
            print(*btlib.get_stack(ref).symbolicated_frames(prefix="    "), sep="\n")

@lldb_command("showmapranges")
def ShowMapRanges(cmd_args=None):
    """Routine to print out info about the specified vm_map and its vm entries
        usage: showmapranges <vm_map>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    map_val = kern.GetValueFromAddress(cmd_args[0], 'vm_map_t')
    print(GetVMMapSummary.header)
    print(GetVMMapSummary(map_val))
    print(GetVMRangeSummary.header)
    for idx in range(2):
        print(GetVMRangeSummary(map_val.user_range[idx], idx))
    return None

def GetResidentPageCount(vmmap):
    resident_pages = 0
    ledger_template = kern.globals.task_ledger_template
    if vmmap.pmap != 0 and vmmap.pmap != kern.globals.kernel_pmap and vmmap.pmap.ledger != 0:
        idx = GetLedgerEntryIndex(ledger_template, "phys_mem")
        phys_mem = GetLedgerEntryBalance(ledger_template, vmmap.pmap.ledger, idx)
        resident_pages = phys_mem // kern.globals.page_size
    return resident_pages

@lldb_type_summary(['_vm_map *', 'vm_map_t'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: >5s} {4: >5s} {5: <20s} {6: <20s} {7: <7s}".format("vm_map", "pmap", "vm_size", "#ents", "rpage", "hint", "first_free", "pgshift"))
def GetVMMapSummary(vmmap):
    """ Display interesting bits from vm_map struct """
    out_string = ""
    format_string = "{0: <#020x} {1: <#020x} {2: <#020x} {3: >5d} {4: >5d} {5: <#020x} {6: <#020x} {7: >7d}"
    vm_size = uint64_t(vmmap.size).value
    resident_pages = GetResidentPageCount(vmmap)
    first_free = 0
    if int(vmmap.holelistenabled) == 0: first_free = vmmap.f_s._first_free
    out_string += format_string.format(vmmap, vmmap.pmap, vm_size, vmmap.hdr.nentries, resident_pages, vmmap.hint, first_free, vmmap.hdr.page_shift)
    return out_string

@lldb_type_summary(['vm_map_entry'])
@header("{0: <20s} {1: <20s} {2: <5s} {3: >7s} {4: <20s} {5: <20s} {6: <4s}".format("entry", "start", "prot", "#page", "object", "offset", "tag"))
def GetVMEntrySummary(vme):
    """ Display vm entry specific information. """
    page_size = kern.globals.page_size
    out_string = ""
    format_string = "{0: <#020x} {1: <#20x} {2: <1x}{3: <1x}{4: <3s} {5: >7d} {6: <#020x} {7: <#020x} {8: >#4x}"
    vme_protection = int(vme.protection)
    vme_max_protection = int(vme.max_protection)
    vme_extra_info_str ="SC-Ds"[int(vme.inheritance)]
    if int(vme.is_sub_map) != 0 :
        vme_extra_info_str +="s"
    elif int(vme.needs_copy) != 0 :
        vme_extra_info_str +="n"
    num_pages = (unsigned(vme.links.end) - unsigned(vme.links.start)) // page_size
    out_string += format_string.format(vme, vme.links.start, vme_protection, vme_max_protection,
            vme_extra_info_str, num_pages, get_vme_object(vme), get_vme_offset(vme), vme.vme_alias)
    return out_string

@lldb_type_summary(['vm_map_range'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: <20s}".format("range", "min_address", "max_address", "size"))
def GetVMRangeSummary(vmrange, idx=0):
    """ Display vm range specific information. """
    range_id = [
        "default",
        "heap"
    ]
    out_string = ""
    format_string = "{0: <20s} {1: <#020x} {2: <#020x} {3: <#20x}"
    range_name = range_id[idx]
    min_address = vmrange.min_address
    max_address = vmrange.max_address
    range_size = max_address - min_address
    out_string += format_string.format(range_name, min_address, max_address, range_size)
    return out_string

# EndMacro: showtaskvme
@lldb_command('showmapwired')
def ShowMapWired(cmd_args=None):
    """ Routine to print out a summary listing of all the entries with wired pages in a vm_map
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    map_val = kern.GetValueFromAddress(cmd_args[0], 'vm_map_t')

@lldb_type_summary(['mount *'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: <12s} {4: <12s} {5: <12s} {6: >6s} {7: <30s} {8: <35s} {9: <30s}".format('volume(mp)', 'mnt_data', 'mnt_devvp', 'flag', 'kern_flag', 'lflag', 'type', 'mnton', 'mntfrom', 'iosched supported'))
def GetMountSummary(mount):
    """ Display a summary of mount on the system
    """
    out_string = ("{mnt: <#020x} {mnt.mnt_data: <#020x} {mnt.mnt_devvp: <#020x} {mnt.mnt_flag: <#012x} " +
                  "{mnt.mnt_kern_flag: <#012x} {mnt.mnt_lflag: <#012x} {vfs.f_fstypename: >6s} " +
                  "{vfs.f_mntonname: <30s} {vfs.f_mntfromname: <35s} {iomode: <30s}").format(mnt=mount, vfs=mount.mnt_vfsstat, iomode=('Yes' if (mount.mnt_ioflags & 0x4) else 'No'))
    return out_string

@lldb_command('showallmounts')
def ShowAllMounts(cmd_args=None):
    """ Print all mount points
    """
    mntlist = kern.globals.mountlist
    print(GetMountSummary.header)
    for mnt in IterateTAILQ_HEAD(mntlist, 'mnt_list'):
        print(GetMountSummary(mnt))
    return

lldb_alias('ShowAllVols', 'showallmounts')

@static_var('output','')
def _GetVnodePathName(vnode, vnodename):
    """ Internal function to get vnode path string from vnode structure.
        params:
            vnode - core.value
            vnodename - str
        returns Nothing. The output will be stored in the static variable.
    """
    if not vnode:
        return
    if int(vnode.v_flag) & 0x1 and int(hex(vnode.v_mount), 16) !=0:
        if int(vnode.v_mount.mnt_vnodecovered):
            _GetVnodePathName(vnode.v_mount.mnt_vnodecovered, str(vnode.v_mount.mnt_vnodecovered.v_name) )
    else:
        _GetVnodePathName(vnode.v_parent, str(vnode.v_parent.v_name))
        _GetVnodePathName.output += "/%s" % vnodename

def GetVnodePath(vnode):
    """ Get string representation of the vnode
        params: vnodeval - value representing vnode * in the kernel
        return: str - of format /path/to/something
    """
    out_str = ''
    if vnode:
            if (int(vnode.v_flag) & 0x000001) and int(hex(vnode.v_mount), 16) != 0 and (int(vnode.v_mount.mnt_flag) & 0x00004000) :
                out_str += "/"
            else:
                _GetVnodePathName.output = ''
                if abs(vnode.v_name) != 0:
                    _GetVnodePathName(vnode, str(vnode.v_name))
                    out_str += _GetVnodePathName.output
                else:
                    out_str += 'v_name = NULL'
                _GetVnodePathName.output = ''
    return out_str


@lldb_command('showvnodepath')
def ShowVnodePath(cmd_args=None):
    """ Prints the path for a vnode
        usage: showvnodepath <vnode>
    """
    if cmd_args != None and len(cmd_args) > 0 :
        vnode_val = kern.GetValueFromAddress(cmd_args[0], 'vnode *')
        if vnode_val:
            print(GetVnodePath(vnode_val))
    return

# Macro: showvnodedev
def GetVnodeDevInfo(vnode):
    """ Internal function to get information from the device type vnodes
        params: vnode - value representing struct vnode *
        return: str - formatted output information for block and char vnode types passed as param
    """
    vnodedev_output = ""
    vblk_type = GetEnumValue('vtype::VBLK')
    vchr_type = GetEnumValue('vtype::VCHR')
    if (vnode.v_type == vblk_type) or (vnode.v_type == vchr_type):
        devnode = Cast(vnode.v_data, 'devnode_t *')
        devnode_dev = devnode.dn_typeinfo.dev
        devnode_major = (devnode_dev >> 24) & 0xff
        devnode_minor = devnode_dev & 0x00ffffff

        # boilerplate device information for a vnode
        vnodedev_output += "Device Info:\n\t vnode:\t\t{:#x}".format(vnode)
        vnodedev_output += "\n\t type:\t\t"
        if (vnode.v_type == vblk_type):
            vnodedev_output += "VBLK"
        if (vnode.v_type == vchr_type):
            vnodedev_output += "VCHR"
        vnodedev_output += "\n\t name:\t\t{:<s}".format(vnode.v_name)
        vnodedev_output += "\n\t major, minor:\t{:d},{:d}".format(devnode_major, devnode_minor)
        vnodedev_output += "\n\t mode\t\t0{:o}".format(unsigned(devnode.dn_mode))
        vnodedev_output += "\n\t owner (u,g):\t{:d} {:d}".format(devnode.dn_uid, devnode.dn_gid)

        # decode device specific data
        vnodedev_output += "\nDevice Specific Information:\t"
        if (vnode.v_type == vblk_type):
            vnodedev_output += "Sorry, I do not know how to decode block devices yet!"
            vnodedev_output += "\nMaybe you can write me!"

        if (vnode.v_type == vchr_type):
            # Device information; this is scanty
            # range check
            if (devnode_major > 42) or (devnode_major < 0):
                vnodedev_output +=  "Invalid major #\n"
            # static assignments in conf
            elif (devnode_major == 0):
                vnodedev_output += "Console mux device\n"
            elif (devnode_major == 2):
                vnodedev_output += "Current tty alias\n"
            elif (devnode_major == 3):
                vnodedev_output += "NULL device\n"
            elif (devnode_major == 4):
                vnodedev_output += "Old pty slave\n"
            elif (devnode_major == 5):
                vnodedev_output += "Old pty master\n"
            elif (devnode_major == 6):
                vnodedev_output += "Kernel log\n"
            elif (devnode_major == 12):
                vnodedev_output += "Memory devices\n"
            # Statically linked dynamic assignments
            elif unsigned(kern.globals.cdevsw[devnode_major].d_open) == unsigned(kern.GetLoadAddressForSymbol('ptmx_open')):
                vnodedev_output += "Cloning pty master not done\n"
                #GetVnodeDevCpty(devnode_major, devnode_minor)
            elif unsigned(kern.globals.cdevsw[devnode_major].d_open) == unsigned(kern.GetLoadAddressForSymbol('ptsd_open')):
                vnodedev_output += "Cloning pty slave not done\n"
                #GetVnodeDevCpty(devnode_major, devnode_minor)
            else:
                vnodedev_output += "RESERVED SLOT\n"
    else:
        vnodedev_output += "{:#x} is not a device".format(vnode)
    return vnodedev_output

@lldb_command('showvnodedev')
def ShowVnodeDev(cmd_args=None):
    """  Routine to display details of all vnodes of block and character device types
         Usage: showvnodedev <address of vnode>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    vnode_val = kern.GetValueFromAddress(cmd_args[0], 'vnode *')
    if not vnode_val:
        print("unknown arguments:", str(cmd_args))
        return False
    print(GetVnodeDevInfo(vnode_val))

# EndMacro: showvnodedev

# Macro: showvnodelocks
def GetVnodeLock(lockf):
    """ Internal function to get information from the given advisory lock
        params: lockf - value representing v_lockf member in struct vnode *
        return: str - formatted output information for the advisory lock
    """
    vnode_lock_output = ''
    lockf_flags = lockf.lf_flags
    lockf_type = lockf.lf_type
    if lockf_flags & 0x20:
        vnode_lock_output += ("{: <8s}").format('flock')
    if lockf_flags & 0x40:
        vnode_lock_output += ("{: <8s}").format('posix')
    if lockf_flags & 0x80:
        vnode_lock_output += ("{: <8s}").format('prov')
    if lockf_flags & 0x10:
        vnode_lock_output += ("{: <4s}").format('W')
    if lockf_flags & 0x400:
        vnode_lock_output += ("{: <8s}").format('ofd')
    else:
        vnode_lock_output += ("{: <4s}").format('.')

    # POSIX file vs advisory range locks
    if lockf_flags & 0x40:
        lockf_proc = Cast(lockf.lf_id, 'proc *')
        vnode_lock_output += ("PID {: <18d}").format(GetProcPID(lockf_proc))
    else:
        vnode_lock_output += ("ID {: <#019x}").format(int(lockf.lf_id))

    # lock type
    if lockf_type == 1:
        vnode_lock_output += ("{: <12s}").format('shared')
    else:
        if lockf_type == 3:
            vnode_lock_output += ("{: <12s}").format('exclusive')
        else:
            if lockf_type == 2:
                vnode_lock_output += ("{: <12s}").format('unlock')
            else:
                vnode_lock_output += ("{: <12s}").format('unknown')

    # start and stop values
    vnode_lock_output += ("{: #018x} ..").format(lockf.lf_start)
    vnode_lock_output += ("{: #018x}\n").format(lockf.lf_end)
    return vnode_lock_output

@header("{0: <3s} {1: <7s} {2: <3s} {3: <21s} {4: <11s} {5: ^19s} {6: ^17s}".format('*', 'type', 'W', 'held by', 'lock type', 'start', 'end'))
def GetVnodeLocksSummary(vnode):
    """ Internal function to get summary of advisory locks for the given vnode
        params: vnode - value representing the vnode object
        return: str - formatted output information for the summary of advisory locks
    """
    out_str = ''
    if vnode:
            lockf_list = vnode.v_lockf
            for lockf_itr in IterateLinkedList(lockf_list, 'lf_next'):
                out_str += ("{: <4s}").format('H')
                out_str += GetVnodeLock(lockf_itr)
                lockf_blocker = lockf_itr.lf_blkhd.tqh_first
                while lockf_blocker:
                    out_str += ("{: <4s}").format('>')
                    out_str += GetVnodeLock(lockf_blocker)
                    lockf_blocker = lockf_blocker.lf_block.tqe_next
    return out_str

@lldb_command('showvnodelocks')
def ShowVnodeLocks(cmd_args=None):
    """  Routine to display list of advisory record locks for the given vnode address
         Usage: showvnodelocks <address of vnode>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    vnode_val = kern.GetValueFromAddress(cmd_args[0], 'vnode *')
    if not vnode_val:
        print("unknown arguments:", str(cmd_args))
        return False
    print(GetVnodeLocksSummary.header)
    print(GetVnodeLocksSummary(vnode_val))

# EndMacro: showvnodelocks

# Macro: showproclocks

@lldb_command('showproclocks')
def ShowProcLocks(cmd_args=None):
    """  Routine to display list of advisory record locks for the given process
         Usage: showproclocks <address of proc>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    proc = kern.GetValueFromAddress(cmd_args[0], 'proc *')
    if not proc:
        print("unknown arguments:", str(cmd_args))
        return False
    out_str = ''
    proc_filedesc = addressof(proc.p_fd)
    fd_ofiles = proc_filedesc.fd_ofiles
    seen = 0

    for fd in range(0, unsigned(proc_filedesc.fd_afterlast)):
        if fd_ofiles[fd]:
            fglob = fd_ofiles[fd].fp_glob
            fo_type = fglob.fg_ops.fo_type
            if fo_type == 1:
                fg_data = Cast(fglob.fg_data, 'void *')
                fg_vnode = Cast(fg_data, 'vnode *')
                name = fg_vnode.v_name
                lockf_itr = fg_vnode.v_lockf
                if lockf_itr:
                    if not seen:
                        print(GetVnodeLocksSummary.header)
                    seen = seen + 1
                    out_str += ("\n( fd {:d}, name ").format(fd)
                    if not name:
                        out_str += "(null) )\n"
                    else:
                        out_str += "{:s} )\n".format(name)
                    print(out_str)  
                    print(GetVnodeLocksSummary(fg_vnode))
    print("\n{0: d} total locks for {1: #018x}".format(seen, proc))

# EndMacro: showproclocks

@lldb_type_summary(["cs_blob *"])
@md_header("{:<20s} {:<20s} {:<8s} {:<8s} {:<15s} {:<15s} {:<15s} {:<20s} {:<15s} {:<40s} {:>50s}", ["vnode", "ro_addr", "base", "start", "end", "mem_size", "mem_offset", "mem_kaddr", "team_id", "cdhash", "vnode_name"])
@header("{:<20s} {:<20s} {:<8s} {:<8s} {:<15s} {:<15s} {:<15s} {:<20s} {:<15s} {:<40s} {:>50s}".format("vnode", "ro_addr", "base", "start", "end", "mem_size", "mem_offset", "mem_kaddr", "team_id", "cdhash", "vnode_name"))
def GetCSBlobSummary(cs_blob, markdown=False):
    """ Get a summary of important information out of csblob
    """
    format_defs = ["{:<#20x}", "{:<#20x}", "{:<8d}", "{:<8d}", "{:<15d}", "{:<15d}", "{:<15d}", "{:<#20x}", "{:<15s}", "{:<40s}", "{:>50s}"]
    if not markdown:
        format_str = " ".join(format_defs)
    else:
        format_str = "|" + "|".join(format_defs) + "|"
    vnode = cs_blob.csb_vnode
    ro_addr = cs_blob.csb_ro_addr
    base_offset = cs_blob.csb_base_offset
    start_offset = cs_blob.csb_start_offset
    end_offset = cs_blob.csb_end_offset
    mem_size = cs_blob.csb_mem_size
    mem_offset = cs_blob.csb_mem_offset
    mem_kaddr = cs_blob.csb_mem_kaddr
    team_id_ptr = int(cs_blob.csb_teamid)
    team_id = ""
    if team_id_ptr != 0:
        team_id = str(cs_blob.csb_teamid)
    elif cs_blob.csb_platform_binary == 1:
        team_id = "platform"
    else:
        team_id = "<no team>"
    
    cdhash = ""
    for i in range(20):
        cdhash += "{:02x}".format(cs_blob.csb_cdhash[i])

    name_ptr = int(vnode.v_name)
    name =""
    if name_ptr != 0:
        name = str(vnode.v_name)

    return format_str.format(vnode, ro_addr, base_offset, start_offset, end_offset, mem_size, mem_offset, mem_kaddr, team_id, cdhash, name)

def iterate_all_cs_blobs(onlyUmanaged=False):
    pmap_cs_enabled = LazyTarget.GetTarget().FindFirstGlobalVariable('pmap_cs').IsValid()
    mntlist = kern.globals.mountlist
    for mntval in IterateTAILQ_HEAD(mntlist, 'mnt_list'):
        for vnode in IterateTAILQ_HEAD(mntval.mnt_vnodelist, 'v_mntvnodes'):
            vtype = int(vnode.v_type) 
            ## We only care about REG files
            if (vtype == 1) and (vnode.v_un.vu_ubcinfo != 0):
                cs_blob_ptr = int(vnode.v_un.vu_ubcinfo.cs_blobs)
                while cs_blob_ptr != 0:
                    cs_blob = addressof(kern.CreateValueFromAddress(cs_blob_ptr, "cs_blob "))
                    if onlyUmanaged and pmap_cs_enabled:
                        pmapEntryPtr = int(cs_blob.csb_csm_obj)
                        if pmapEntryPtr != 0:
                            pmapEntry = addressof(kern.CreateValueFromAddress(pmapEntryPtr, "struct pmap_cs_code_directory"))
                            if int(pmapEntry.managed) != 0:
                                continue
                    cs_blob_ptr = int(cs_blob.csb_next)
                    yield cs_blob


@lldb_command('showallcsblobs')
def ShowAllCSBlobs(cmd_args=[]):
    """ Display info about all cs_blobs associated with vnodes
        Usage: showallcsblobs [unmanaged] [markdown]
        If you pass in unmanaged, the output will be restricted to those objects
        that are stored in VM_KERN_MEMORY_SECURITY as kobjects

        If you pass in markdown, the output will be a nicely formatted markdown
        table that can be pasted around. 
    """
    options = {"unmanaged", "markdown"}
    if len(set(cmd_args).difference(options)) > 0:
        print("Unknown options: see help showallcsblobs for usage")
        return

    markdown = "markdown" in cmd_args
    if not markdown:
        print(GetCSBlobSummary.header)
    else:
        print(GetCSBlobSummary.markdown)
    sorted_blobs = sorted(iterate_all_cs_blobs(onlyUmanaged="unmanaged" in cmd_args), key=lambda blob: int(blob.csb_mem_size), reverse=True)
    for csblob in sorted_blobs:
        print(GetCSBlobSummary(csblob, markdown=markdown))

def meanof(data):
    return sum(data) / len(data)
def pstddev(data):
    mean = meanof(data)
    ssum = 0
    for v in data:
        ssum += (v - mean) ** 2
    return math.sqrt(ssum / len(data))

@lldb_command("triagecsblobmemory")
def TriageCSBlobMemoryUsage(cmd_args=[]):
    """ Display statistics on cs_blob memory usage in the VM_KERN_MEMORY_SECURITY tag
        Usage: triagecsblobmemory [dump] [all]

        If you pass in all, the statistics will NOT be restricted to the VM_KERN_MEMORY_SECURITY tag.
        
        if you pass in dump, after the triage is finished a json blob with vnode names and 
        the associated memory usage will be generated.
    """

    options = {"dump", "all"}
    if len(set(cmd_args).difference(options)) > 0:
        print("Unknown options: see help triagecsblobmemory for usage")
        return

    sorted_blobs = sorted(iterate_all_cs_blobs(onlyUmanaged="all" not in cmd_args), key=lambda blob: int(blob.csb_mem_size), reverse=True)
    blob_usages = [int(csblob.csb_mem_size) for csblob in sorted_blobs]

    print("Total unmanaged blobs: ", len(blob_usages))
    print("Total unmanaged memory usage {:.0f}K".format(sum(blob_usages)/1024))
    print("Average blob size: {:.0f} +- {:.0f} bytes".format(meanof(blob_usages), pstddev(blob_usages)))
    if "dump" in cmd_args:
        perps = dict()
        for blob in sorted_blobs:
            name_ptr = int(blob.csb_vnode.v_name)
            if name_ptr != 0:
                name = str(blob.csb_vnode.v_name)
                if name in perps:
                    perps[name].append(int(blob.csb_mem_size))
                else:
                    perps[name] = [int(blob.csb_mem_size)]
            else:
                print("Skipped blob because it has no vnode name:", blob)

        print(json.dumps(perps))


@lldb_type_summary(['vnode_t', 'vnode *'])
@header("{0: <20s} {1: >8s} {2: >9s} {3: >8s} {4: <20s} {5: <6s} {6: <20s} {7: <6s} {8: <6s} {9: <35s}".format('vnode', 'usecount', 'kusecount', 'iocount', 'v_data', 'vtype', 'parent', 'mapped', 'cs_version', 'name'))
def GetVnodeSummary(vnode):
    """ Get a summary of important information out of vnode
    """
    out_str = ''
    format_string = "{0: <#020x} {1: >8d} {2: >8d} {3: >8d} {4: <#020x} {5: <6s} {6: <#020x} {7: <6s} {8: <6s} {9: <35s}"
    usecount = int(vnode.v_usecount)
    kusecount = int(vnode.v_kusecount)
    iocount = int(vnode.v_iocount)
    v_data_ptr = int(hex(vnode.v_data), 16)
    vtype = int(vnode.v_type)
    vtype_str = "%d" % vtype
    vnode_types = ['VNON', 'VREG', 'VDIR', 'VBLK', 'VCHR', 'VLNK', 'VSOCK', 'VFIFO', 'VBAD', 'VSTR', 'VCPLX']  # see vnode.h for enum type definition
    if vtype >= 0 and vtype < len(vnode_types):
        vtype_str = vnode_types[vtype]
    parent_ptr = int(hex(vnode.v_parent), 16)
    name_ptr = int(hex(vnode.v_name), 16)
    name =""
    if name_ptr != 0:
        name = str(vnode.v_name)
    elif int(vnode.v_tag) == 16 :
        try:
            cnode = Cast(vnode.v_data, 'cnode *')
            name = "hfs: %s" % str( Cast(cnode.c_desc.cd_nameptr, 'char *'))
        except:
            print("Failed to cast 'cnode *' type likely due to missing HFS kext symbols.")
            print("Please run 'addkext -N com.apple.filesystems.hfs.kext' to load HFS kext symbols.")
            sys.exit(1)
    mapped = '-'
    csblob_version = '-'
    if (vtype == 1) and (vnode.v_un.vu_ubcinfo != 0):
        csblob_version = '{: <6d}'.format(vnode.v_un.vu_ubcinfo.cs_add_gen)
        # Check to see if vnode is mapped/unmapped
        if (vnode.v_un.vu_ubcinfo.ui_flags & 0x8) != 0:
            mapped = '1'
        else:
            mapped = '0'
    out_str += format_string.format(vnode, usecount, kusecount, iocount, v_data_ptr, vtype_str, parent_ptr, mapped, csblob_version, name)
    return out_str

@lldb_command('showallvnodes')
def ShowAllVnodes(cmd_args=None):
    """ Display info about all vnodes
    """
    mntlist = kern.globals.mountlist
    print(GetVnodeSummary.header)
    for mntval in IterateTAILQ_HEAD(mntlist, 'mnt_list'):
        for vnodeval in IterateTAILQ_HEAD(mntval.mnt_vnodelist, 'v_mntvnodes'):
            print(GetVnodeSummary(vnodeval))
    return

@lldb_command('showvnode')
def ShowVnode(cmd_args=None):
    """ Display info about one vnode
        usage: showvnode <vnode>
    """
    if cmd_args is None or len(cmd_args) == 0:
        print("Please provide valid vnode argument. Type help showvnode for help.")
        return
    vnodeval = kern.GetValueFromAddress(cmd_args[0],'vnode *')
    print(GetVnodeSummary.header)
    print(GetVnodeSummary(vnodeval))

@lldb_command('showvolvnodes')
def ShowVolVnodes(cmd_args=None):
    """ Display info about all vnodes of a given mount_t
    """
    if cmd_args is None or len(cmd_args) == 0:
        print("Please provide a valide mount_t argument. Try 'help showvolvnodes' for help")
        return
    mntval = kern.GetValueFromAddress(cmd_args[0], 'mount_t')
    print(GetVnodeSummary.header)
    for vnodeval in IterateTAILQ_HEAD(mntval.mnt_vnodelist, 'v_mntvnodes'):
        print(GetVnodeSummary(vnodeval))
    return

@lldb_command('showvolbusyvnodes')
def ShowVolBusyVnodes(cmd_args=None):
    """ Display info about busy (iocount!=0) vnodes of a given mount_t
    """
    if cmd_args is None or len(cmd_args) == 0:
        print("Please provide a valide mount_t argument. Try 'help showvolbusyvnodes' for help")
        return

    mount_address = ArgumentStringToInt(cmd_args[0])
    mntval = addressof(kern.CreateValueFromAddress(mount_address, 'struct mount'))
    print(GetVnodeSummary.header)
    for vnodeval in IterateTAILQ_HEAD(mntval.mnt_vnodelist, 'v_mntvnodes'):
        if int(vnodeval.v_iocount) != 0:
            print(GetVnodeSummary(vnodeval))

@lldb_command('showallbusyvnodes')
def ShowAllBusyVnodes(cmd_args=None):
    """ Display info about all busy (iocount!=0) vnodes
    """
    mntlistval = kern.globals.mountlist
    for mntval in IterateTAILQ_HEAD(mntlistval, 'mnt_list'):
        ShowVolBusyVnodes([hex(mntval)])

@lldb_command('print_vnode')
def PrintVnode(cmd_args=None):
    """ Prints out the fields of a vnode struct
        Usage: print_vnode <vnode>
    """
    if cmd_args is None or len(cmd_args) == 0:
        print("Please provide valid vnode argument. Type help print_vnode for help.")
        return
    ShowVnode(cmd_args)

@lldb_command('showworkqvnodes')
def ShowWorkqVnodes(cmd_args=None):
    """ Print the vnode worker list
        Usage: showworkqvnodes <struct mount *>
    """
    if cmd_args is None or len(cmd_args) == 0:
        print("Please provide valid mount argument. Type help showworkqvnodes for help.")
        return

    mp = kern.GetValueFromAddress(cmd_args[0], 'mount *')
    vp = Cast(mp.mnt_workerqueue.tqh_first, 'vnode *')
    print(GetVnodeSummary.header)
    while int(vp) != 0:
        print(GetVnodeSummary(vp))
        vp = vp.v_mntvnodes.tqe_next

@lldb_command('shownewvnodes')
def ShowNewVnodes(cmd_args=None):
    """ Print the new vnode list
        Usage: shownewvnodes <struct mount *>
    """
    if cmd_args is None or len(cmd_args) == 0:
        print("Please provide valid mount argument. Type help shownewvnodes for help.")
        return
    mp = kern.GetValueFromAddress(cmd_args[0], 'mount *')
    vp = Cast(mp.mnt_newvnodes.tqh_first, 'vnode *')
    print(GetVnodeSummary.header)
    while int(vp) != 0:
        print(GetVnodeSummary(vp))
        vp = vp.v_mntvnodes.tqe_next


@lldb_command('showprocvnodes')
def ShowProcVnodes(cmd_args=None):
    """ Routine to print out all the open fds which are vnodes in a process
        Usage: showprocvnodes <proc *>
    """
    if cmd_args is None or len(cmd_args) == 0:
        print("Please provide valid proc argument. Type help showprocvnodes for help.")
        return

    proc_address = ArgumentStringToInt(cmd_args[0])
    procptr = addressof(kern.CreateValueFromAddress(proc_address, 'proc'))
    fdptr = addressof(procptr.p_fd)
    if int(fdptr.fd_cdir) != 0:
        print('{0: <25s}\n{1: <s}\n{2: <s}'.format('Current Working Directory:', GetVnodeSummary.header, GetVnodeSummary(fdptr.fd_cdir)))
    if int(fdptr.fd_rdir) != 0:
        print('{0: <25s}\n{1: <s}\n{2: <s}'.format('Current Root Directory:', GetVnodeSummary.header, GetVnodeSummary(fdptr.fd_rdir)))
    print('\n' + '{0: <5s} {1: <7s} {2: <20s} '.format('fd', 'flags', 'fileglob') + GetVnodeSummary.header)

    for fd in range(fdptr.fd_nfiles):
        fproc = fdptr.fd_ofiles[fd]
        if unsigned(fproc) != 0:
            fglob = fproc.fp_glob

            if (unsigned(fglob) != 0) and (unsigned(fglob.fg_ops.fo_type) == 1):
                flags = ""
                if (fproc.fp_flags & GetEnumValue('fileproc_flags_t', 'FP_CLOEXEC')):
                    flags += 'E'
                if (fproc.fp_flags & GetEnumValue('fileproc_flags_t', 'FP_CLOFORK')):
                    flags += 'F'
                if (fdptr.fd_ofileflags[fd] & 4):
                    flags += 'R'
                if (fdptr.fd_ofileflags[fd] & 8):
                    flags += 'C'

                # Strip away PAC to avoid LLDB accessing memory through signed pointers below.
                fgdata = kern.GetValueFromAddress(kern.StripKernelPAC(fglob.fg_data), 'vnode *')
                print('{0: <5d} {1: <7s} {2: <#020x} '.format(fd, flags, fglob) + GetVnodeSummary(fgdata))

@lldb_command('showallprocvnodes')
def ShowAllProcVnodes(cmd_args=None):
    """ Routine to print out all the open fds which are vnodes
    """

    procptr = Cast(kern.globals.allproc.lh_first, 'proc *')
    while procptr and int(procptr) != 0:
        print('{:<s}'.format("=" * 106))
        print(GetProcInfo(procptr))
        ShowProcVnodes([str(int(procptr))])
        procptr = procptr.p_list.le_next

@xnudebug_test('test_vnode')
def TestShowAllVnodes(kernel_target, config, lldb_obj, isConnected ):
    """ Test the functionality of vnode related commands
        returns
         - False on failure
         - True on success
    """
    if not isConnected:
        print("Target is not connected. Cannot test memstats")
        return False
    res = lldb.SBCommandReturnObject()
    lldb_obj.debugger.GetCommandInterpreter().HandleCommand("showallvnodes", res)
    result = res.GetOutput()
    if len(result.split("\n")) > 2 and result.find('VREG') != -1 and len(result.splitlines()[2].split()) > 5:
        return True
    else:
        return False

#Macro: showlock
@lldb_type_summary(['lck_mtx_t *'])
@header("===== Mutex Lock Summary =====")
def GetMutexLockSummary(mtx):
    """ Summarize mutex lock with important information.
        params:
        mtx: value - obj representing a mutex lock in kernel
        returns:
        out_str - summary of the mutex lock
    """
    if not mtx:
        return "Invalid lock value: 0x0"

    grp = getLockGroupFromCgidInternal(mtx.lck_mtx_grp)

    if kern.arch == "x86_64":
        out_str = "Lock Type            : MUTEX\n"
        if mtx.lck_mtx_state == 0x07fe2007 :
            out_str += "*** Tagged as DESTROYED ({:#x}) ***\n".format(mtx.lck_mtx_state)
        out_str += "Number of Waiters   : {mtx.lck_mtx_waiters:#d}\n".format(mtx=mtx)
        out_str += "ILocked             : {mtx.lck_mtx_ilocked:#d}\n".format(mtx=mtx)
        out_str += "MLocked             : {mtx.lck_mtx_mlocked:#d}\n".format(mtx=mtx)
        out_str += "Pri                 : {mtx.lck_mtx_pri:#d}\n".format(mtx=mtx)
        out_str += "Spin                : {mtx.lck_mtx_spin:#d}\n".format(mtx=mtx)
        out_str += "Profiling           : {mtx.lck_mtx_profile:#d}\n".format(mtx=mtx)
        out_str += "Group               : {grp.lck_grp_name:s} ({grp:#x})\n".format(grp=grp)
        out_str += "Owner Thread        : {:#x}\n".format(getThreadFromCtidInternal(mtx.lck_mtx_owner))
    else:
        out_str  = "Lock Type           : MUTEX\n"
        if mtx.lck_mtx_type != GetEnumValue('lck_type_t', 'LCK_TYPE_MUTEX') or mtx.lck_mtx.data == 0xc0fe2007:
            out_str += "*** Likely DESTROYED ***\n"
        out_str += "ILocked             : {mtx.lck_mtx.ilocked:#d}\n".format(mtx=mtx)
        out_str += "Spin                : {mtx.lck_mtx.spin_mode:#d}\n".format(mtx=mtx)
        out_str += "Needs Wakeup        : {mtx.lck_mtx.needs_wakeup:#d}\n".format(mtx=mtx)
        out_str += "Profiling           : {mtx.lck_mtx.profile:#d}\n".format(mtx=mtx)
        out_str += "Group               : {grp.lck_grp_name:s} ({grp:#x})\n".format(grp=grp)
        out_str += "Owner Thread        : {:#x}\n".format(getThreadFromCtidInternal(mtx.lck_mtx.owner))
        out_str += "Turnstile           : {:#x}\n".format(getTurnstileFromCtidInternal(mtx.lck_mtx_tsid))

        mcs_ilk_next_map = {}

        if mtx.lck_mtx.as_tail or mtx.lck_mtx.ilk_tail:
            for cpu in range(0, kern.globals.zpercpu_early_count):
                mcs = kern.PERCPU_GET('lck_mcs', cpu).mcs_mtx
                try:
                    if unsigned(mcs.lmm_ilk_current) != unsigned(mtx):
                        continue
                except:
                    continue
                if mcs.lmm_ilk_next:
                    mcs_ilk_next_map[unsigned(mcs.lmm_ilk_next)] = cpu | 0x4000

        idx = unsigned(mtx.lck_mtx.as_tail)
        s   = set()
        q   = []
        while idx:
            mcs = addressof(kern.PERCPU_GET('lck_mcs', idx & 0x3fff).mcs_mtx)
            q.append(((idx & 0x3fff), mcs))
            if idx in s: break
            s.add(idx)
            idx = unsigned(mcs.lmm_as_prev)
        q.reverse()

        from misc import GetCpuDataForCpuID
        out_str += "Adapt. spin tail    : {mtx.lck_mtx.as_tail:d}\n".format(mtx=mtx)
        for (cpu, mcs) in q:
            out_str += "    CPU {:2d}, thread {:#x}, node {:d}\n".format(
                    cpu, GetCpuDataForCpuID(cpu).cpu_active_thread, mcs)

        idx = unsigned(mtx.lck_mtx.ilk_tail)
        q   = []
        s   = set()
        while idx:
            mcs = addressof(kern.PERCPU_GET('lck_mcs', idx & 0x3fff).mcs_mtx)
            q.append((idx & 0x3fff, mcs))
            if idx in s: break
            s.add(idx)
            idx = unsigned(mcs_ilk_next_map.get(unsigned(mcs), 0))
        q.reverse()

        out_str += "Interlock tail      : {mtx.lck_mtx.ilk_tail:d}\n".format(mtx=mtx)
        for (cpu, mcs) in q:
            out_str += "    CPU {:2d}, thread {:#x}, node {:d}\n".format(
                    cpu, GetCpuDataForCpuID(cpu).cpu_active_thread, mcs)

    return out_str

@lldb_type_summary(['hw_lck_ticket_t'])
@header("===== HWTicketLock Summary =====")
def GetHWTicketLockSummary(tu, show_header):
    """ Summarize hw ticket lock with important information.
        params:
        tu value - obj representing a hw_lck_ticket_t in kernel
        returns:
        out_str - summary of the lock
    """
    out_str = ""
    if tu.lck_type != GetEnumValue('lck_type_t', 'LCK_TYPE_TICKET'):
        out_str += "HW Ticket Lock does not have the right type\n"
    elif show_header:
        out_str += "Lock Type\t\t: HW TICKET LOCK\n"
    if not(tu.lck_valid):
        out_str += "HW Ticket Lock was invalidated\n"
    out_str += "Current Ticket\t\t: {:#x}\n".format(tu.cticket)
    out_str += "Next Ticket\t\t: {:#x}\n".format(tu.nticket)
    if tu.lck_is_pv:
        out_str += "Lock is a paravirtualized lock\n"
    return out_str

@lldb_type_summary(['lck_ticket_t *'])
@header("===== TicketLock Summary =====")
def GetTicketLockSummary(tlock):
    """ Summarize ticket lock with important information.
        params:
        tlock: value - obj representing a ticket lock in kernel
        returns:
        out_str - summary of the ticket lock
    """
    if not tlock:
        return "Invalid lock value: 0x0"

    out_str = "Lock Type\t\t: TICKETLOCK\n"
    if tlock.lck_ticket_type != GetEnumValue('lck_type_t', 'LCK_TYPE_TICKET'):
        out_str += "Ticket Lock Invalid\n"
        if tlock.lck_ticket_type == GetEnumValue('lck_type_t', 'LCK_TYPE_NONE'):
            out_str += "*** Likely DESTROYED ***\n"
        return out_str
    out_str += GetHWTicketLockSummary(tlock.tu, False)
    out_str += "Owner Thread\t\t: "
    if tlock.lck_ticket_owner == 0:
        out_str += "None\n"
    else:
        out_str += "{:#x}\n".format(getThreadFromCtidInternal(tlock.lck_ticket_owner))
    return out_str


@lldb_type_summary(['lck_spin_t *'])
@header("===== SpinLock Summary =====")
def GetSpinLockSummary(spinlock):
    """ Summarize spinlock with important information.
        params:
        spinlock: value - obj representing a spinlock in kernel
        returns:
        out_str - summary of the spinlock
    """
    if not spinlock:
        return "Invalid lock value: 0x0"

    out_str = "Lock Type\t\t: SPINLOCK\n"
    if kern.arch == "x86_64":
        out_str += "Interlock\t\t: {:#x}\n".format(spinlock.interlock)
        return out_str 
    LCK_SPIN_TYPE = 0x11
    if spinlock.type != LCK_SPIN_TYPE:
        out_str += "Spinlock Invalid"
        return out_str
    lock_data = spinlock.hwlock.lock_data
    if lock_data == 1:
        out_str += "Invalid state: interlock is locked but no owner\n"
        return out_str
    out_str += "Owner Thread\t\t: "
    if lock_data == 0:
        out_str += "None\n"
    else:
        out_str += "{:#x}\n".format(lock_data & ~0x1)
        if (lock_data & 1) == 0:
            out_str += "Invalid state: owned but interlock bit is not set\n"
    return out_str

@lldb_type_summary(['lck_rw_t *'])
@header("===== RWLock Summary =====")
def GetRWLockSummary(rwlock):
    """ Summarize rwlock with important information.
        params:
        rwlock: value - obj representing a lck_rw_lock in kernel
        returns:
        out_str - summary of the rwlock
    """
    if not rwlock:
        return "Invalid lock value: 0x0"

    out_str = "Lock Type\t\t: RWLOCK\n"
    if rwlock.lck_rw_type != GetEnumValue('lck_type_t', 'LCK_TYPE_RW'):
        out_str += "*** Likely DESTROYED ***\n"
    lock_word = rwlock.lck_rw
    out_str += "Blocking\t\t: "
    if lock_word.can_sleep == 0:
        out_str += "FALSE\n"
    else:
        out_str += "TRUE\n"
    if lock_word.priv_excl == 0:
        out_str += "Recusive\t\t: shared recursive\n"
    out_str += "Interlock\t\t: {:#x}\n".format(lock_word.interlock)
    out_str += "Writer bits\t\t: "
    if lock_word.want_upgrade == 0 and lock_word.want_excl == 0:
        out_str += "-\n"
    else:
        if lock_word.want_upgrade == 1:
            out_str += "Read-to-write upgrade requested"
            if lock_word.want_excl == 1:
                out_str += ","
            else:
                out_str += "\n"
        if lock_word.want_excl == 1:
            out_str += "Write ownership requested\n"
    out_str += "Write owner\t\t: {:#x}\n".format(getThreadFromCtidInternal(rwlock.lck_rw_owner))
    out_str += "Reader(s)    \t\t: "
    if lock_word.shared_count > 0:
        out_str += "{:#d}\n".format(lock_word.shared_count)
    else:
        out_str += "No readers\n"
    if lock_word.r_waiting == 1:
        out_str += "Reader(s) blocked\t: TRUE\n"
    if lock_word.w_waiting == 1:
        out_str += "Writer(s) blocked\t: TRUE\n"
    return out_str

@lldb_command('showlock', 'HMRST')
def ShowLock(cmd_args=None, cmd_options={}):
    """ Show info about a lock - its state and owner thread details
        Usage: showlock <address of a lock>
        -H : to consider <addr> as hw_lck_ticket_t 
        -M : to consider <addr> as lck_mtx_t 
        -R : to consider <addr> as lck_rw_t
        -S : to consider <addr> as lck_spin_t 
        -T : to consider <addr> as lck_ticket_t 
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Please specify the address of the lock whose info you want to view.")

    summary_str = ""
    addr = cmd_args[0]
    ## from osfmk/arm/locks.h
    if "-M" in cmd_options:
        lock_mtx = kern.GetValueFromAddress(addr, 'struct lck_mtx_s *')
        summary_str = GetMutexLockSummary(lock_mtx)
    elif "-S" in cmd_options:
        lock_spin = kern.GetValueFromAddress(addr, 'struct lck_spin_s *')
        summary_str = GetSpinLockSummary(lock_spin)
    elif "-H" in cmd_options:
        tu = kern.GetValueFromAddress(addr, 'union hw_lck_ticket_s *')
        summary_str = GetHWTicketLockSummary(tu, True)
    elif "-T" in cmd_options:
        tlock = kern.GetValueFromAddress(addr, 'struct lck_ticket_s *')
        summary_str = GetTicketLockSummary(tlock)
    elif "-R" in cmd_options:
        lock_rw = kern.GetValueFromAddress(addr, 'struct lck_rw_s *')
        summary_str = GetRWLockSummary(lock_rw)
    else:
        summary_str = "Please specify supported lock option(-H/-M/-R/-S/-T)"

    print(summary_str)

#EndMacro: showlock

def getThreadRW(thread, debug, elem_find, force_print):
    """ Helper routine for finding per thread rw lock:
        returns:
        String with info
    """
    out = ""
    ## if we are not in debug mode do not access thread.rw_lock_held
    if not debug:
        if not force_print:
            if thread.rwlock_count == 0:
                return out
        out = "{:<19s} {:>19s} \n".format("Thread", "rwlock_count")
        out += "{:<#19x} ".format(thread)
        out += "{:>19d} ".format(thread.rwlock_count)
        return out

    rw_locks_held = thread.rw_lock_held
    if not force_print:
        if thread.rwlock_count == 0 and rw_locks_held.rwld_locks_acquired == 0:
            return out

    out = "{:<19s} {:>19s} {:>19s} {:>29s}\n".format("Thread", "rwlock_count", "rwlock_acquired", "RW_Debug_info_missing")
    out += "{:<#19x} ".format(thread)
    out += "{:>19d} ".format(thread.rwlock_count)
    out += "{:>19d} ".format(rw_locks_held.rwld_locks_acquired)

    if rw_locks_held.rwld_overflow:
        out += "{:>29s}\n".format("TRUE")
    else:
        out += "{:>29s}\n".format("FALSE")

    kmem = kmemory.KMem.get_shared()
    found = set()
    if rw_locks_held.rwld_locks_saved > 0:
        lock_entry = rw_locks_held.rwld_locks
        num_entry = sizeof(lock_entry) // sizeof(lock_entry[0])
        out += "{:>10s} {:<19s} {:>10s} {:>10s} {:>10s} {:<19s}\n".format(" ", "Lock", "Write", "Read", " ", "Caller")
        for i in range(num_entry):
            entry = lock_entry[i]
            if entry.rwlde_lock:
                out += "{:>10s} ".format(" ")
                found.add(hex(entry.rwlde_lock))
                out += "{:<#19x} ".format(entry.rwlde_lock)
                write = 0
                read = 0
                if entry.rwlde_mode_count < 0:
                    write = 1
                if entry.rwlde_mode_count > 0:
                    read = entry.rwlde_mode_count
                out += "{:>10d} ".format(write)
                out += "{:>10d} ".format(read)
                out += "{:>10s} ".format(" ")
                # rwlde_caller_packing not available in release kernel
                if kmem.rwlde_caller_packing:
                    caller = kmem.rwlde_caller_packing.unpack(unsigned(entry.rwlde_caller_packed))
                    out += "{:<#19x}\n".format(caller)

    if elem_find != 0:
        if elem_find in found:
            return out
        else:
            return ""
    else:
        return out

def rwLockDebugDisabled():
    ## LCK_OPTION_DISABLE_RW_DEBUG 0x10 from lock_types.h
    if (kern.globals.LcksOpts and 0x10) == 0x10:
        return True
    else:
        return False

@lldb_command('showthreadrwlck')
def ShowThreadRWLck(cmd_args = None):
    """ Routine to print a best effort summary of rwlocks held
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Please specify the thread pointer")

    thread = kern.GetValueFromAddress(cmd_args[0], 'thread_t')
    if not thread:
        raise ArgumentError("Invalid thread pointer")
        return

    debug = True
    if rwLockDebugDisabled():
        print("WARNING: Best effort per-thread rwlock tracking is OFF\n")
        debug = False

    string = getThreadRW(thread, debug, 0, True)
    if len(string): print(string)


# EndMacro: showthreadrwlck

@lldb_command('showallrwlckheld')
def ShowAllRWLckHeld(cmd_args = None):
    """ Routine to print a summary listing of all read/writer locks
        tracked per thread
    """
    debug = True
    if rwLockDebugDisabled():
        print("WARNING: Best effort per-thread rwlock tracking is OFF\n")
        debug = False

    for t in kern.tasks:
        for th in IterateQueue(t.threads, 'thread *', 'task_threads'):
            string = getThreadRW(th, debug, 0, False)
            if len(string): print(string)

# EndMacro: showallrwlckheld

@lldb_command('tryfindrwlckholders')
def tryFindRwlckHolders(cmd_args = None):
    """ Best effort routing to find the current holders of
        a rwlock
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Please specify a rw_lock_t pointer")

    if rwLockDebugDisabled():
        print("WARNING: Best effort per-thread rwlock tracking is OFF\n")

    print("This is a best effort mechanism, if threads have lock info missing we might not be able to find the lock.\n")
    rw_to_find = cmd_args[0]
    for t in kern.tasks:
        for th in IterateQueue(t.threads, 'thread *', 'task_threads'):
            string = getThreadRW(th, True, rw_to_find, False)
            if len(string): print(string)

    return
# EndMacro: tryfindrwlckholders

def clz64(var):
    var = unsigned(var)
    if var == 0:
        return 64

    c = 63
    while (var & (1 << c)) == 0:
        c -= 1
    return 63 - c

def getThreadFromCtidInternal(ctid):
    CTID_BASE_TABLE = 1 << 10
    CTID_MASK       = (1 << 20) - 1
    nonce           = unsigned(kern.globals.ctid_nonce)

    if not ctid:
        return kern.GetValueFromAddress(0, 'struct thread *')

    # unmangle the compact TID
    ctid = unsigned(ctid ^ nonce)
    if ctid == CTID_MASK:
        ctid = nonce

    index = clz64(CTID_BASE_TABLE) - clz64(ctid | (CTID_BASE_TABLE - 1)) + 1
    table = kern.globals.ctid_table
    return cast(table.cidt_array[index][ctid], 'struct thread *')

def getLockGroupFromCgidInternal(cgid):
    CGID_BASE_TABLE = 1 << 10
    CGID_MASK       = 0xffff

    cgid &= CGID_MASK
    if not cgid:
        return kern.GetValueFromAddress(0, 'lck_grp_t *')

    index = clz64(CGID_BASE_TABLE) - clz64(cgid | (CGID_BASE_TABLE - 1)) + 1
    table = kern.globals.lck_grp_table
    return cast(table.cidt_array[index][cgid], 'lck_grp_t *')

def getTurnstileFromCtidInternal(ctid):
    CTSID_BASE_TABLE = 1 << 10
    CTSID_MASK       = (1 << 20) - 1
    nonce            = unsigned(kern.globals.ctsid_nonce)

    if not ctid:
        return kern.GetValueFromAddress(0, 'struct turnstile *')

    # unmangle the compact TID
    ctid = unsigned(ctid ^ nonce)
    if ctid == CTSID_MASK:
        ctid = nonce

    index = clz64(CTSID_BASE_TABLE) - clz64(ctid | (CTSID_BASE_TABLE - 1)) + 1
    table = kern.globals.ctsid_table
    return cast(table.cidt_array[index][ctid], 'struct turnstile *')

@lldb_command('getthreadfromctid')
def getThreadFromCtid(cmd_args = None):
    """ Get the thread pointer associated with the ctid
        Usage: getthreadfromctid <ctid>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Please specify a ctid")

    ctid   = ArgumentStringToInt(cmd_args[0])
    thread = getThreadFromCtidInternal(ctid)
    if thread:
        print("Thread pointer {:#x}".format(thread))
    else :
        print("Thread not found")

@lldb_command('getturnstilefromctsid')
def getTurnstileFromCtid(cmd_args = None):
    """ Get the turnstile pointer associated with the ctsid
        Usage: getturnstilefromctsid <ctid>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Please specify a ctid")

    ctid = ArgumentStringToInt(cmd_args[0])
    ts   = getTurnstileFromCtidInternal(ctid)
    if ts:
        print("Turnstile pointer {:#x}".format(ts))
    else :
        print("Turnstile not found")

# EndMacro: showkernapfsreflock

@lldb_command('showkernapfsreflock')
def showAPFSReflock(cmd_args = None):
    """ Show info about a show_kern_apfs_reflock_t
        Usage: show_kern_apfs_reflock <kern_apfs_reflock_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Please specify a kern_apfs_reflock_t pointer")

    raw_addr = cmd_args[0]
    reflock = kern.GetValueFromAddress(raw_addr, 'kern_apfs_reflock_t')
    summary = "\n"
    if reflock.kern_apfs_rl_owner != 0 :
        summary += "Owner ctid \t: \t{reflock.kern_apfs_rl_owner:#d} ".format(reflock=reflock)
        ctid = reflock.kern_apfs_rl_owner
        thread = getThreadFromCtidInternal(ctid)
        summary += "(thread_t {:#x})\n".format(thread)
    else :
        summary += "No Owner\n"
    summary += "Waiters \t: \t{reflock.kern_apfs_rl_waiters:#d}\n".format(reflock=reflock)
    summary += "Delayed Free \t: \t{reflock.kern_apfs_rl_delayed_free:#d}\n".format(reflock=reflock)
    summary += "Wake \t\t: \t{reflock.kern_apfs_rl_wake:#d}\n".format(reflock=reflock)
    summary += "Allocated \t: \t{reflock.kern_apfs_rl_allocated:#d}\n".format(reflock=reflock)
    summary += "Allow Force \t: \t{reflock.kern_apfs_rl_allow_force:#d}\n".format(reflock=reflock)
    summary += "RefCount \t: \t{reflock.kern_apfs_rl_count:#d}\n".format(reflock=reflock)

    print(summary)
    return
# EndMacro: showkernapfsreflock

#Macro: showbootermemorymap
@lldb_command('showbootermemorymap')
def ShowBooterMemoryMap(cmd_args=None):
    """ Prints out the phys memory map from kernelBootArgs
        Supported only on x86_64
    """
    if kern.arch != 'x86_64':
        print("showbootermemorymap not supported on this architecture")
        return

    out_string = ""
    
    # Memory type map
    memtype_dict = {
            0:  'Reserved',
            1:  'LoaderCode',
            2:  'LoaderData',
            3:  'BS_code',
            4:  'BS_data',
            5:  'RT_code',
            6:  'RT_data',
            7:  'Convention',
            8:  'Unusable',
            9:  'ACPI_recl',
            10: 'ACPI_NVS',
            11: 'MemMapIO',
            12: 'MemPortIO',
            13: 'PAL_code'
        }

    boot_args = kern.globals.kernelBootArgs
    msize = boot_args.MemoryMapDescriptorSize
    mcount = boot_args.MemoryMapSize // unsigned(msize)
    
    out_string += "{0: <12s} {1: <19s} {2: <19s} {3: <19s} {4: <10s}\n".format("Type", "Physical Start", "Number of Pages", "Virtual Start", "Attributes")
    
    i = 0
    while i < mcount:
        mptr = kern.GetValueFromAddress(unsigned(boot_args.MemoryMap) + kern.VM_MIN_KERNEL_ADDRESS + unsigned(i*msize), 'EfiMemoryRange *')
        mtype = unsigned(mptr.Type)
        if mtype in memtype_dict:
            out_string += "{0: <12s}".format(memtype_dict[mtype])
        else:
            out_string += "{0: <12s}".format("UNKNOWN")

        if mptr.VirtualStart == 0:
            out_string += "{0: #019x} {1: #019x} {2: <19s} {3: #019x}\n".format(mptr.PhysicalStart, mptr.NumberOfPages, ' '*19, mptr.Attribute)
        else:
            out_string += "{0: #019x} {1: #019x} {2: #019x} {3: #019x}\n".format(mptr.PhysicalStart, mptr.NumberOfPages, mptr.VirtualStart, mptr.Attribute)
        i = i + 1
    
    print(out_string)
#EndMacro: showbootermemorymap

@lldb_command('show_all_purgeable_objects')
def ShowAllPurgeableVmObjects(cmd_args=None):
    """ Routine to print a summary listing of all the purgeable vm objects
    """
    print("\n--------------------    VOLATILE OBJECTS    --------------------\n")
    ShowAllPurgeableVolatileVmObjects()
    print("\n--------------------  NON-VOLATILE OBJECTS  --------------------\n")
    ShowAllPurgeableNonVolatileVmObjects()

@lldb_command('show_all_purgeable_nonvolatile_objects')
def ShowAllPurgeableNonVolatileVmObjects(cmd_args=None):
    """ Routine to print a summary listing of all the vm objects in
        the purgeable_nonvolatile_queue
    """

    nonvolatile_total = lambda:None
    nonvolatile_total.objects = 0
    nonvolatile_total.vsize = 0
    nonvolatile_total.rsize = 0
    nonvolatile_total.wsize = 0
    nonvolatile_total.csize = 0
    nonvolatile_total.disowned_objects = 0
    nonvolatile_total.disowned_vsize = 0
    nonvolatile_total.disowned_rsize = 0
    nonvolatile_total.disowned_wsize = 0
    nonvolatile_total.disowned_csize = 0

    queue_len = kern.globals.purgeable_nonvolatile_count
    queue_head = kern.globals.purgeable_nonvolatile_queue

    print('purgeable_nonvolatile_queue:{: <#018x}  purgeable_volatile_count:{:d}\n'.format(kern.GetLoadAddressForSymbol('purgeable_nonvolatile_queue'),queue_len))
    print('N:non-volatile  V:volatile  E:empty  D:deny\n')

    print('{:>6s} {:<6s} {:18s} {:1s} {:>6s} {:>16s} {:>10s} {:>10s} {:>10s}   {:>3s} {:18s} {:>6s} {:<20s}\n'.format("#","#","object","P","refcnt","size (pages)","resid","wired","compressed","tag","owner","pid","process"))
    idx = 0
    for object in IterateQueue(queue_head, 'struct vm_object *', 'objq'):
        idx += 1
        ShowPurgeableNonVolatileVmObject(object, idx, queue_len, nonvolatile_total)
    print("disowned objects:{:<10d}  [ virtual:{:<10d}  resident:{:<10d}  wired:{:<10d}  compressed:{:<10d} ]\n".format(nonvolatile_total.disowned_objects, nonvolatile_total.disowned_vsize, nonvolatile_total.disowned_rsize, nonvolatile_total.disowned_wsize, nonvolatile_total.disowned_csize))
    print("     all objects:{:<10d}  [ virtual:{:<10d}  resident:{:<10d}  wired:{:<10d}  compressed:{:<10d} ]\n".format(nonvolatile_total.objects, nonvolatile_total.vsize, nonvolatile_total.rsize, nonvolatile_total.wsize, nonvolatile_total.csize))


def ShowPurgeableNonVolatileVmObject(object, idx, queue_len, nonvolatile_total):
    """  Routine to print out a summary a VM object in purgeable_nonvolatile_queue
        params: 
            object - core.value : a object of type 'struct vm_object *'
        returns:
            None
    """
    page_size = kern.globals.page_size
    if object.purgable == 0:
        purgable = "N"
    elif object.purgable == 1:
        purgable = "V"
    elif object.purgable == 2:
        purgable = "E"
    elif object.purgable == 3:
        purgable = "D"
    else:
        purgable = "?"
    if object.pager == 0:
        compressed_count = 0
    else:
        compressor_pager = Cast(object.pager, 'compressor_pager *')
        compressed_count = compressor_pager.cpgr_num_slots_occupied

    print("{:>6d}/{:<6d} {: <#018x} {:1s} {:>6d} {:>16d} {:>10d} {:>10d} {:>10d}  {:>3d} {: <#018x} {:>6d} {:<20s}\n".format(idx,queue_len,object,purgable,object.ref_count,object.vo_un1.vou_size // page_size,object.resident_page_count,object.wired_page_count,compressed_count, object.vo_ledger_tag, object.vo_un2.vou_owner,GetProcPIDForObjectOwner(object.vo_un2.vou_owner),GetProcNameForObjectOwner(object.vo_un2.vou_owner)))

    nonvolatile_total.objects += 1
    nonvolatile_total.vsize += object.vo_un1.vou_size // page_size
    nonvolatile_total.rsize += object.resident_page_count
    nonvolatile_total.wsize += object.wired_page_count
    nonvolatile_total.csize += compressed_count
    if object.vo_un2.vou_owner == 0:
        nonvolatile_total.disowned_objects += 1
        nonvolatile_total.disowned_vsize += object.vo_un1.vou_size // page_size
        nonvolatile_total.disowned_rsize += object.resident_page_count
        nonvolatile_total.disowned_wsize += object.wired_page_count
        nonvolatile_total.disowned_csize += compressed_count


@lldb_command('show_all_purgeable_volatile_objects')
def ShowAllPurgeableVolatileVmObjects(cmd_args=None):
    """ Routine to print a summary listing of all the vm objects in
        the purgeable queues
    """
    volatile_total = lambda:None
    volatile_total.objects = 0
    volatile_total.vsize = 0
    volatile_total.rsize = 0
    volatile_total.wsize = 0
    volatile_total.csize = 0
    volatile_total.disowned_objects = 0
    volatile_total.disowned_vsize = 0
    volatile_total.disowned_rsize = 0
    volatile_total.disowned_wsize = 0
    volatile_total.disowned_csize = 0

    purgeable_queues = kern.globals.purgeable_queues
    print("---------- OBSOLETE\n")
    ShowPurgeableQueue(purgeable_queues[0], volatile_total)
    print("\n\n---------- FIFO\n")
    ShowPurgeableQueue(purgeable_queues[1], volatile_total)
    print("\n\n---------- LIFO\n")
    ShowPurgeableQueue(purgeable_queues[2], volatile_total)

    print("disowned objects:{:<10d}  [ virtual:{:<10d}  resident:{:<10d}  wired:{:<10d}  compressed:{:<10d} ]\n".format(volatile_total.disowned_objects, volatile_total.disowned_vsize, volatile_total.disowned_rsize, volatile_total.disowned_wsize, volatile_total.disowned_csize))
    print("     all objects:{:<10d}  [ virtual:{:<10d}  resident:{:<10d}  wired:{:<10d}  compressed:{:<10d} ]\n".format(volatile_total.objects, volatile_total.vsize, volatile_total.rsize, volatile_total.wsize, volatile_total.csize))
    purgeable_count = kern.globals.vm_page_purgeable_count
    purgeable_wired_count = kern.globals.vm_page_purgeable_wired_count
    if purgeable_count != volatile_total.rsize or purgeable_wired_count != volatile_total.wsize:
        mismatch = "<---------  MISMATCH\n"
    else:
        mismatch = ""
    print("vm_page_purgeable_count:                           resident:{:<10d}  wired:{:<10d}  {:s}\n".format(purgeable_count, purgeable_wired_count, mismatch))


def ShowPurgeableQueue(qhead, volatile_total):
    print("----- GROUP 0\n")
    ShowPurgeableGroup(qhead.objq[0], volatile_total)
    print("----- GROUP 1\n")
    ShowPurgeableGroup(qhead.objq[1], volatile_total)
    print("----- GROUP 2\n")
    ShowPurgeableGroup(qhead.objq[2], volatile_total)
    print("----- GROUP 3\n")
    ShowPurgeableGroup(qhead.objq[3], volatile_total)
    print("----- GROUP 4\n")
    ShowPurgeableGroup(qhead.objq[4], volatile_total)
    print("----- GROUP 5\n")
    ShowPurgeableGroup(qhead.objq[5], volatile_total)
    print("----- GROUP 6\n")
    ShowPurgeableGroup(qhead.objq[6], volatile_total)
    print("----- GROUP 7\n")
    ShowPurgeableGroup(qhead.objq[7], volatile_total)

def ShowPurgeableGroup(qhead, volatile_total):
    idx = 0
    for object in IterateQueue(qhead, 'struct vm_object *', 'objq'):
        if idx == 0:
#            print "{:>6s} {:18s} {:1s} {:>6s} {:>16s} {:>10s} {:>10s} {:>10s}   {:18s} {:>6s} {:<20s} {:18s} {:>6s} {:<20s} {:s}\n".format("#","object","P","refcnt","size (pages)","resid","wired","compressed","owner","pid","process","volatilizer","pid","process","")
            print("{:>6s} {:18s} {:1s} {:>6s} {:>16s} {:>10s} {:>10s} {:>10s}   {:>3s} {:18s} {:>6s} {:<20s}\n".format("#","object","P","refcnt","size (pages)","resid","wired","compressed","tag","owner","pid","process"))
        idx += 1
        ShowPurgeableVolatileVmObject(object, idx, volatile_total)

def ShowPurgeableVolatileVmObject(object, idx, volatile_total):
    """  Routine to print out a summary a VM object in a purgeable queue
        params: 
            object - core.value : a object of type 'struct vm_object *'
        returns:
            None
    """
##   if int(object.vo_un2.vou_owner) != int(object.vo_purgeable_volatilizer):
#        diff=" !="
##    else:
#        diff="  "
    page_size = kern.globals.page_size
    if object.purgable == 0:
        purgable = "N"
    elif object.purgable == 1:
        purgable = "V"
    elif object.purgable == 2:
        purgable = "E"
    elif object.purgable == 3:
        purgable = "D"
    else:
        purgable = "?"
    if object.pager == 0:
        compressed_count = 0
    else:
        compressor_pager = Cast(object.pager, 'compressor_pager *')
        compressed_count = compressor_pager.cpgr_num_slots_occupied
#    print "{:>6d} {: <#018x} {:1s} {:>6d} {:>16d} {:>10d} {:>10d} {:>10d} {: <#018x} {:>6d} {:<20s}   {: <#018x} {:>6d} {:<20s} {:s}\n".format(idx,object,purgable,object.ref_count,object.vo_un1.vou_size/page_size,object.resident_page_count,object.wired_page_count,compressed_count,object.vo_un2.vou_owner,GetProcPIDForObjectOwner(object.vo_un2.vou_owner),GetProcNameForObjectOwner(object.vo_un2.vou_owner),object.vo_purgeable_volatilizer,GetProcPIDForObjectOwner(object.vo_purgeable_volatilizer),GetProcNameForObjectOwner(object.vo_purgeable_volatilizer),diff)
    print("{:>6d} {: <#018x} {:1s} {:>6d} {:>16d} {:>10d} {:>10d} {:>10d}   {:>3d} {: <#018x} {:>6d} {:<20s}\n".format(idx,object,purgable,object.ref_count,object.vo_un1.vou_size // page_size,object.resident_page_count,object.wired_page_count,compressed_count, object.vo_ledger_tag, object.vo_un2.vou_owner,GetProcPIDForObjectOwner(object.vo_un2.vou_owner),GetProcNameForObjectOwner(object.vo_un2.vou_owner)))
    volatile_total.objects += 1
    volatile_total.vsize += object.vo_un1.vou_size // page_size
    volatile_total.rsize += object.resident_page_count
    volatile_total.wsize += object.wired_page_count
    volatile_total.csize += compressed_count
    if object.vo_un2.vou_owner == 0:
        volatile_total.disowned_objects += 1
        volatile_total.disowned_vsize += object.vo_un1.vou_size // page_size
        volatile_total.disowned_rsize += object.resident_page_count
        volatile_total.disowned_wsize += object.wired_page_count
        volatile_total.disowned_csize += compressed_count


def GetCompressedPagesForObject(obj):
    """Stuff
    """
    pager = Cast(obj.pager, 'compressor_pager_t')
    return pager.cpgr_num_slots_occupied
    """  # commented code below
    if pager.cpgr_num_slots > 128:
        slots_arr = pager.cpgr_slots.cpgr_islots
        num_indirect_slot_ptr = (pager.cpgr_num_slots + 127) / 128
        index = 0
        compressor_slot = 0
        compressed_pages = 0
        while index < num_indirect_slot_ptr:
            compressor_slot = 0
            if slots_arr[index]:
                while compressor_slot < 128:
                    if slots_arr[index][compressor_slot]:
                        compressed_pages += 1
                    compressor_slot += 1
            index += 1
    else:
        slots_arr = pager.cpgr_slots.cpgr_dslots
        compressor_slot = 0
        compressed_pages = 0
        while compressor_slot < pager.cpgr_num_slots:
            if slots_arr[compressor_slot]:
                compressed_pages += 1
            compressor_slot += 1
    return compressed_pages
    """

def ShowTaskVMEntries(task, show_pager_info, show_all_shadows):
    """  Routine to print out a summary listing of all the entries in a vm_map
        params: 
            task - core.value : a object of type 'task *'
        returns:
            None
    """
    print("vm_map entries for task " + hex(task))
    print(GetTaskSummary.header)
    print(GetTaskSummary(task))
    if not task.map:
        print(f"Task {0: <#020x} has map = 0x0")
        return None
    showmapvme(task.map, 0, 0, show_pager_info, show_all_shadows)

@lldb_command("showmapvme", "A:B:F:PRST")
def ShowMapVME(cmd_args=None, cmd_options={}, entry_filter=None):
    """Routine to print out info about the specified vm_map and its vm entries
        usage: showmapvme <vm_map> [-A start] [-B end] [-S] [-P]
        Use -A <start> flag to start at virtual address <start>
        Use -B <end> flag to end at virtual address <end>
        Use -F <virtaddr> flag to find just the VME containing the given VA
        Use -S flag to show VM object shadow chains
        Use -P flag to show pager info (mapped file, compressed pages, ...)
        Use -R flag to reverse order
        Use -T to show red-black tree pointers
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    show_pager_info = False
    show_all_shadows = False
    show_upl_info = False
    show_rb_tree = False
    start_vaddr = 0
    end_vaddr = 0
    reverse_order = False
    if "-A" in cmd_options:
        start_vaddr = ArgumentStringToInt(cmd_options['-A'])
    if "-B" in cmd_options:
        end_vaddr = ArgumentStringToInt(cmd_options['-B'])
    if "-F" in cmd_options:
        start_vaddr = ArgumentStringToInt(cmd_options['-F'])
        end_vaddr = start_vaddr
    if "-P" in cmd_options:
        show_pager_info = True
    if "-S" in cmd_options:
        show_all_shadows = True
    if "-R" in cmd_options:
        reverse_order = True
    if "-T" in cmd_options:
        show_rb_tree = True
    if "-U" in cmd_options:
        show_upl_info = True
    map = kern.GetValueFromAddress(cmd_args[0], 'vm_map_t')
    showmapvme(map, start_vaddr, end_vaddr, show_pager_info, show_all_shadows, reverse_order, show_rb_tree, entry_filter, show_upl_info)

@lldb_command("showmapcopyvme", "A:B:F:PRSTU")
def ShowMapCopyVME(cmd_args=None, cmd_options={}):
    """Routine to print out info about the specified vm_map_copy and its vm entries
        usage: showmapcopyvme <vm_map_copy> [-A start] [-B end] [-S] [-P]
        Use -A <start> flag to start at virtual address <start>
        Use -B <end> flag to end at virtual address <end>
        Use -F <virtaddr> flag to find just the VME containing the given VA
        Use -S flag to show VM object shadow chains
        Use -P flag to show pager info (mapped file, compressed pages, ...)
        Use -R flag to reverse order
        Use -T to show red-black tree pointers
        Use -U flag to show UPL info
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    show_pager_info = False
    show_all_shadows = False
    show_rb_tree = False
    start_vaddr = 0
    end_vaddr = 0
    reverse_order = False
    if "-A" in cmd_options:
        start_vaddr = unsigned(int(cmd_options['-A'], 16))
    if "-B" in cmd_options:
        end_vaddr = unsigned(int(cmd_options['-B'], 16))
    if "-F" in cmd_options:
        start_vaddr = unsigned(int(cmd_options['-F'], 16))
        end_vaddr = start_vaddr
    if "-P" in cmd_options:
        show_pager_info = True
    if "-S" in cmd_options:
        show_all_shadows = True
    if "-R" in cmd_options:
        reverse_order = True
    if "-T" in cmd_options:
        show_rb_tree = True
    map = kern.GetValueFromAddress(cmd_args[0], 'vm_map_copy_t')
    showmapcopyvme(map, start_vaddr, end_vaddr, show_pager_info, show_all_shadows, reverse_order, show_rb_tree)

@lldb_command("showmaptpro", "A:B:F:PRST")
def ShowMapTPRO(cmd_args=None, cmd_options={}):
    """Routine to print out info about the specified vm_map and its TPRO entries
        usage: showmaptpro <vm_map> [-A start] [-B end] [-S] [-P]
        Use -A <start> flag to start at virtual address <start>
        Use -B <end> flag to end at virtual address <end>
        Use -F <virtaddr> flag to find just the VME containing the given VA
        Use -S flag to show VM object shadow chains
        Use -P flag to show pager info (mapped file, compressed pages, ...)
        Use -R flag to reverse order
        Use -T to show red-black tree pointers
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

   
    def filter_entries(vme):
        try:
            if vme.used_for_tpro:
                return True
        except AttributeError:
            pass
        return False

    ShowMapVME(cmd_args, cmd_options, filter_entries)

@header("{:>20s} {:>15s} {:>15s} {:>15s} {:>20s} {:>20s} {:>20s} {:>20s} {:>20s} {:>15s}".format(
    "VM page", "vmp_busy", "vmp_dirty", "vmp_cleaning", "vmp_on_specialq", "vmp_object", "Object Unpacked", "Pager", "paging_in_progress", "activity_in_progress"))
@lldb_command("showvmpage", "OC", fancy=True)
def ShowVMPage(cmd_args=None, cmd_options={}, O=None):
    """Routine to print out a VM Page 
        usage: showvmpage <vm_page> [-O] [-C]
        -O: show VM object info for page.
        -C: search page in stacks 
    """
    
    if cmd_args == None or len(cmd_args) < 1:
        raise ArgumentError("invalid arguments")
        
    show_object_info = False
    show_callchain = False
    if "-O" in cmd_options:
        show_object_info = True
    if "-C" in cmd_options:
        show_callchain = True	
        
    page = kern.GetValueFromAddress(cmd_args[0], 'vm_page_t')
    if not page:
        raise ArgumentError("Unknown arguments: {:s}".format(cmd_args[0]))

    pager=-1
    paging_in_progress=-1
    activity_in_progress=-1
    if(page.vmp_object):
        m_object_val = _vm_page_unpack_ptr(page.vmp_object)
        object = kern.GetValueFromAddress(m_object_val, 'vm_object_t')
        if not object:
            print("No valid object: {:s}".format(m_object_val))

        pager=object.pager
        paging_in_progress=object.paging_in_progress
        activity_in_progress=object.activity_in_progress
    
    print(ShowVMPage.header)
    print("{:>#20x} {:>15d} {:>15d} {:>15d} {:>20d} {:>#20x} {:>#20x} {:>#20x} {:>20d} {:>15d}".format(
    page, page.vmp_busy, page.vmp_dirty, page.vmp_cleaning, page.vmp_on_specialq, page.vmp_object, object, pager, paging_in_progress, activity_in_progress))
    
    if show_object_info:
        print("\nPrinting object info for given page",object)
        showvmobject(object, 0, 0, 1, 1)

    if show_callchain: 
        print("Searching for Page: ",hex(page))
        show_call_chain(hex(page), O)

        print("Searching for object: ",hex(m_object_val))
        show_call_chain(hex(m_object_val),O)

        print("Searching for Pager: ",hex(pager))
        show_call_chain(hex(pager),O)    

@lldb_command("showvmobject", "A:B:PRSTU")
def ShowVMObject(cmd_args=None, cmd_options={}):
    """Routine to print out a VM object and its shadow chain
        usage: showvmobject <vm_object> [-S] [-P]
        -S: show VM object shadow chain
        -P: show pager info (mapped file, compressed pages, ...)
        -U: show UPL info
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    show_pager_info = False
    show_all_shadows = False
    show_upl_info = False

    if "-P" in cmd_options:
        show_pager_info = True
    if "-S" in cmd_options:
        show_all_shadows = True
    if "-U" in cmd_options:
        show_upl_info = True
    object = kern.GetValueFromAddress(cmd_args[0], 'vm_object_t')
    showvmobject(object, 0, 0, show_pager_info, show_all_shadows, show_upl_info)

def PrintUPLSummary(upl, spacing=''):
    indented_spacing = spacing + " "*4

    page_size = kern.globals.page_size
    print(f"{spacing}  {VT.Bold}{'Address (upl_t)':<18} {'Creator (thread)':<18} {'# pages':<10} {'associated UPL'}{VT.EndBold}")

    num_pages = math.ceil(upl.u_size / page_size)
    associated_upl = f'{upl.associated_upl:#018x}' if upl.associated_upl else ''
    print(f'{spacing}  {upl:#018x} {upl.upl_creator:#018x}   {num_pages:<8} {associated_upl}')

    first_page_info = True
    for page_ind in range(num_pages):
        if first_page_info:
            print(f"{indented_spacing} {VT.Bold}{'upl_index':<12} {'Address (upl_page_info *)':<28} {'ppnum':<24} {'page (vm_page_t)':<28}{VT.EndBold}")
            first_page_info = False

        # lite_list is a bitfield marking pages locked by UPL
        bits_per_element = sizeof(upl.lite_list[0])
        bitfield_number = int(page_ind / bits_per_element)
        bit_in_bitfield = (1 << (page_ind % bits_per_element))
        if upl.lite_list[bitfield_number] & (bit_in_bitfield):
            upl_page_info = upl.page_list[page_ind]
            ppnum = upl_page_info.phys_addr
            page = _vm_page_get_page_from_phys(ppnum)
            page_addr = '' if page is None else f'{unsigned(addressof(page)):<#28x}'

            print(f"{indented_spacing} {page_ind:<12} {unsigned(addressof(upl_page_info)):<#28x} {ppnum:<#24x} {page_addr}")

def PrintVMObjUPLs(uplq_head):
    spacing = " "*19
    for upl in IterateQueue(addressof(uplq_head), 'upl_t', 'uplq'):
        PrintUPLSummary(upl, spacing)

def showvmobject(object, offset=0, size=0, show_pager_info=False, show_all_shadows=False, show_upl_info=False):
    page_size = kern.globals.page_size
    vnode_pager_ops = kern.globals.vnode_pager_ops
    vnode_pager_ops_addr = unsigned(addressof(vnode_pager_ops))
    depth = 0
    if size == 0 and object != 0 and object.internal:
        size = object.vo_un1.vou_size
    while object != 0:
        depth += 1
        if not show_all_shadows and depth != 1 and object.shadow != 0:
            offset += unsigned(object.vo_un2.vou_shadow_offset)
            object = object.shadow
            continue
        if object.copy_strategy == 0:
            copy_strategy="N"
        elif object.copy_strategy == 2:
            copy_strategy="D"
        elif object.copy_strategy == 4:
            copy_strategy="S"
        elif object.copy_strategy == 6:
            copy_strategy="F";
        else:
            copy_strategy=str(object.copy_strategy)
        if object.internal:
            internal = "internal"
        else:
            internal = "external"
        purgeable = "NVED"[int(object.purgable)]
        pager_string = ""
        if object.phys_contiguous:
            pager_string = pager_string + "phys_contig {:#018x}:{:#018x} ".format(unsigned(object.vo_un2.vou_shadow_offset), unsigned(object.vo_un1.vou_size))
        pager = object.pager
        if show_pager_info and pager != 0:
            if object.internal:
                pager_string = pager_string + "-> compressed:{:d} ({:#018x})".format(GetCompressedPagesForObject(object), object.pager)
            elif unsigned(pager.mo_pager_ops) == vnode_pager_ops_addr:
                vnode_pager = Cast(pager,'vnode_pager *')
                pager_string = pager_string + "-> " + GetVnodePath(vnode_pager.vnode_handle)
            else:
                pager_string = pager_string + "-> {:s}:{: <#018x}".format(pager.mo_pager_ops.memory_object_pager_name, pager)
        print("{:>18d} {:#018x}:{:#018x} {: <#018x} ref:{:<6d} ts:{:1d} strat:{:1s} purg:{:1s} {:s} wtag:{:d} ({:d} {:d} {:d}) {:s}".format(depth,offset,offset+size,object,object.ref_count,object.true_share,copy_strategy,purgeable,internal,object.wire_tag,unsigned(object.vo_un1.vou_size) // page_size,object.resident_page_count,object.wired_page_count,pager_string))
#       print "        #{:<5d} obj {: <#018x} ref:{:<6d} ts:{:1d} strat:{:1s} {:s} size:{:<10d} wired:{:<10d} resident:{:<10d} reusable:{:<10d}".format(depth,object,object.ref_count,object.true_share,copy_strategy,internal,object.vo_un1.vou_size/page_size,object.wired_page_count,object.resident_page_count,object.reusable_page_count)

        if show_upl_info:
            PrintVMObjUPLs(object.uplq)

        offset += unsigned(object.vo_un2.vou_shadow_offset)
        object = object.shadow

def showmapvme(map, start_vaddr, end_vaddr, show_pager_info=False, show_all_shadows=False, reverse_order=False, show_rb_tree=False, entry_filter=None, show_upl_info=False):
    rsize = GetResidentPageCount(map)
    print("{:<18s} {:<18s} {:<18s} {:>10s} {:>18s} {:>18s}:{:<18s} {:<7s}".format("vm_map","pmap","size","#ents","rsize","start","end","pgshift"))
    print("{: <#018x} {: <#018x} {:#018x} {:>10d} {:>18d} {:#018x}:{:#018x} {:>7d}".format(map,map.pmap,unsigned(map.size),map.hdr.nentries,rsize,map.hdr.links.start,map.hdr.links.end,map.hdr.page_shift))
    showmaphdrvme(map.hdr, map.pmap, start_vaddr, end_vaddr, show_pager_info, show_all_shadows, reverse_order, show_rb_tree, entry_filter, show_upl_info)

def showmapcopyvme(mapcopy, start_vaddr=0, end_vaddr=0, show_pager_info=True, show_all_shadows=True, reverse_order=False, show_rb_tree=False, show_upl_info=False):
    print("{:<18s} {:<18s} {:<18s} {:>10s} {:>18s} {:>18s}:{:<18s} {:<7s}".format("vm_map_copy","offset","size","#ents","rsize","start","end","pgshift"))
    print("{: <#018x} {:#018x} {:#018x} {:>10d} {:>18d} {:#018x}:{:#018x} {:>7d}".format(mapcopy,mapcopy.offset,mapcopy.size,mapcopy.c_u.hdr.nentries,0,mapcopy.c_u.hdr.links.start,mapcopy.c_u.hdr.links.end,mapcopy.c_u.hdr.page_shift))
    showmaphdrvme(mapcopy.c_u.hdr, 0, start_vaddr, end_vaddr, show_pager_info, show_all_shadows, reverse_order, show_rb_tree, None, show_upl_info)

def showmaphdrvme(maphdr, pmap, start_vaddr, end_vaddr, show_pager_info, show_all_shadows, reverse_order, show_rb_tree, entry_filter, show_upl_info):
    page_size = kern.globals.page_size
    if hasattr(kern.globals, 'compressor_object'):
        compressor_object = kern.globals.compressor_object
    else:
        compressor_object = -1;
    vme_list_head = maphdr.links
    vme_ptr_type = GetType('vm_map_entry *')
    print("{:<18s} {:>18s}:{:<18s} {:>10s} {:<8s} {:<16s} {:<18s} {:<18s}".format("entry","start","end","#pgs","tag.kmod","prot&flags","object","offset"))
    last_end = unsigned(maphdr.links.start)
    skipped_entries = 0
    for vme in IterateQueue(vme_list_head, vme_ptr_type, "links", reverse_order):
        links = vme.links
        vme_start = links.start
        vme_end = links.end
        vme_start_val = unsigned(vme_start)
        vme_end_val = unsigned(vme_end)
        if start_vaddr != 0 and end_vaddr != 0:
            if vme_start_val > end_vaddr:
                break
            if unsigned(vme_end) <= start_vaddr:
                last_end = vme_end_val
                skipped_entries = skipped_entries + 1
                continue
            if skipped_entries != 0:
                print("... skipped {:d} entries ...".format(skipped_entries))
                skipped_entries = 0
        if entry_filter and not entry_filter(vme):
            continue
        if vme_start_val != last_end:
            print("{:18s} {:#018x}:{:#018x} {:>10d}".format("------------------",last_end,vme_start,(vme_start_val - last_end) // page_size))
        last_end = vme_end_val
        size = vme_end_val - vme_start_val
        object = get_vme_object(vme)
        object_val = int(object)
        if object_val == 0:
            object_str = "{: <#018x}".format(object)
        elif vme.is_sub_map:
            object_str = None

            if object_val == kern.globals.bufferhdr_map:
                object_str = "BUFFERHDR_MAP"
            elif object_val == kern.globals.mb_map:
                object_str = "MB_MAP"
            elif object_val == kern.globals.bsd_pageable_map:
                object_str = "BSD_PAGEABLE_MAP"
            elif object_val == kern.globals.ipc_kernel_map:
                object_str = "IPC_KERNEL_MAP"
            elif object_val == kern.globals.ipc_kernel_copy_map:
                object_str = "IPC_KERNEL_COPY_MAP"
            elif hasattr(kern.globals, 'io_submap') and object_val == kern.globals.io_submap:
                object_str = "IO_SUBMAP"
            elif hasattr(kern.globals, 'pgz_submap') and object_val == kern.globals.pgz_submap:
                object_str = "ZALLOC:PGZ"
            elif hasattr(kern.globals, 'compressor_map') and object_val == kern.globals.compressor_map:
                object_str = "COMPRESSOR_MAP"
            elif hasattr(kern.globals, 'g_kext_map') and object_val == kern.globals.g_kext_map:
                object_str = "G_KEXT_MAP"
            elif hasattr(kern.globals, 'vector_upl_submap') and object_val == kern.globals.vector_upl_submap:
                object_str = "VECTOR_UPL_SUBMAP"
            elif object_val == kern.globals.zone_meta_map:
                object_str = "ZALLOC:META"
            else:
                for i in range(0, int(GetEnumValue('zone_submap_idx_t', 'Z_SUBMAP_IDX_COUNT'))):
                    if object_val == kern.globals.zone_submaps[i]:
                        object_str = "ZALLOC:{:s}".format(GetEnumName('zone_submap_idx_t', i, 'Z_SUBMAP_IDX_'))
                        break
            if object_str is None:
                object_str = "submap:{: <#018x}".format(object)
        else:
            if object_val == kern.globals.kernel_object_default:
                object_str = "KERNEL_OBJECT"
            elif hasattr(kern.globals, 'kernel_object_tagged') and object_val == kern.globals.kernel_object_tagged:
                object_str = "KERNEL_OBJECT_TAGGED"
            elif object_val == compressor_object:
                object_str = "COMPRESSOR_OBJECT"
            else:
                object_str = "{: <#018x}".format(object)
        offset = get_vme_offset(vme)
        tag = unsigned(vme.vme_alias)

        vme_protection = vme.protection
        protection = ""
        if vme_protection & 0x1:
            protection +="r"
        else:
            protection += "-"
        if vme_protection & 0x2:
            protection += "w"
        else:
            protection += "-"
        if vme_protection & 0x4:
            protection += "x"
        else:
            protection += "-"

        vme_max_protection = vme.max_protection
        max_protection = ""
        if vme_max_protection & 0x1:
            max_protection += "r"
        else:
            max_protection += "-"
        if vme_max_protection & 0x2:
            max_protection += "w"
        else:
            max_protection += "-"
        if vme_max_protection & 0x4:
            max_protection += "x"
        else:
            max_protection += "-"

        vme_flags = ""
        if vme.is_sub_map:
            vme_flags += "s"
        if vme.needs_copy:
            vme_flags += "n"
        if vme.use_pmap:
            vme_flags += "p"
        if vme.wired_count:
            vme_flags += "w"
        if vme.used_for_jit:
            vme_flags += "j"
        if vme.vme_permanent:
            vme_flags += "!"
        try:
            if vme.used_for_tpro:
                vme_flags += "t"
        except AttributeError:
            pass

        tagstr = ""
        if pmap == kern.globals.kernel_pmap:
            xsite = Cast(kern.globals.vm_allocation_sites[tag],'OSKextAccount *')
            if xsite and xsite.site.flags & 0x0200:
                tagstr = ".{:<3d}".format(xsite.loadTag)
        rb_info = ""
        if show_rb_tree:
            rb_info = "l={: <#018x} r={: <#018x} p={: <#018x}".format(vme.store.entry.rbe_left, vme.store.entry.rbe_right, vme.store.entry.rbe_parent)
        print("{: <#018x} {:#018x}:{:#018x} {:>10d} {:>3d}{:<4s}  {:3s}/{:3s}/{:<8s} {:<18s} {:<#18x} {:s}".format(vme,vme_start,vme_end,(vme_end_val-vme_start_val) // page_size,tag,tagstr,protection,max_protection,vme_flags,object_str,offset, rb_info))
        if (show_pager_info or show_all_shadows) and vme.is_sub_map == 0 and object_val != 0:
            pass # object is already intialized
        else:
            object = 0
        showvmobject(object, offset, size, show_pager_info, show_all_shadows, show_upl_info)
    if start_vaddr != 0 or end_vaddr != 0:
        print("...")
    elif unsigned(maphdr.links.end) > last_end:
        print("{:18s} {:#018x}:{:#018x} {:>10d}".format("------------------",last_end,maphdr.links.end,(unsigned(maphdr.links.end) - last_end) // page_size))
    return None

def CountMapTags(map, tagcounts, slow):
    page_size = unsigned(kern.globals.page_size)
    vme_list_head = map.hdr.links
    vme_ptr_type = GetType('vm_map_entry *')
    for vme in IterateQueue(vme_list_head, vme_ptr_type, "links"):
        object = get_vme_object(vme)
        tag = vme.vme_alias
        if object == kern.globals.kernel_object_default or (hasattr(kern.globals, 'kernel_object_tagged') and object == kern.globals.kernel_object_tagged):
            count = 0
            if not slow:
                count = unsigned(vme.links.end - vme.links.start) // page_size
            else:
                addr = unsigned(vme.links.start)
                while addr < unsigned(vme.links.end):
                    hash_id = _calc_vm_page_hash(object, addr)
                    page_list = kern.globals.vm_page_buckets[hash_id].page_list
                    page = _vm_page_unpack_ptr(page_list)
                    while (page != 0):
                        vmpage = kern.GetValueFromAddress(page, 'vm_page_t')
                        if (addr == unsigned(vmpage.vmp_offset)) and (object == vm_object_t(_vm_page_unpack_ptr(vmpage.vmp_object))):
                            if (not vmpage.vmp_local) and (vmpage.vmp_wire_count > 0):
                                count += 1
                            break
                        page = _vm_page_unpack_ptr(vmpage.vmp_next_m)
                    addr += page_size
            tagcounts[tag] += count
        elif vme.is_sub_map:
            CountMapTags(Cast(object,'vm_map_t'), tagcounts, slow)
    return None

def CountWiredObject(object, tagcounts):
    tagcounts[unsigned(object.wire_tag)] += object.wired_page_count
    return None

def GetKmodIDName(kmod_id):
    kmod_val = kern.globals.kmod
    for kmod in IterateLinkedList(kmod_val, 'next'):
        if (kmod.id == kmod_id):
            return "{:<50s}".format(kmod.name)
    return "??"

FixedTags = {
    0:  "VM_KERN_MEMORY_NONE",
    1:  "VM_KERN_MEMORY_OSFMK",
    2:  "VM_KERN_MEMORY_BSD",
    3:  "VM_KERN_MEMORY_IOKIT",
    4:  "VM_KERN_MEMORY_LIBKERN",
    5:  "VM_KERN_MEMORY_OSKEXT",
    6:  "VM_KERN_MEMORY_KEXT",
    7:  "VM_KERN_MEMORY_IPC",
    8:  "VM_KERN_MEMORY_STACK",
    9:  "VM_KERN_MEMORY_CPU",
    10: "VM_KERN_MEMORY_PMAP",
    11: "VM_KERN_MEMORY_PTE",
    12: "VM_KERN_MEMORY_ZONE",
    13: "VM_KERN_MEMORY_KALLOC",
    14: "VM_KERN_MEMORY_COMPRESSOR",
    15: "VM_KERN_MEMORY_COMPRESSED_DATA",
    16: "VM_KERN_MEMORY_PHANTOM_CACHE",
    17: "VM_KERN_MEMORY_WAITQ",
    18: "VM_KERN_MEMORY_DIAG",
    19: "VM_KERN_MEMORY_LOG",
    20: "VM_KERN_MEMORY_FILE",
    21: "VM_KERN_MEMORY_MBUF",
    22: "VM_KERN_MEMORY_UBC",
    23: "VM_KERN_MEMORY_SECURITY",
    24: "VM_KERN_MEMORY_MLOCK",
    25: "VM_KERN_MEMORY_REASON",
    26: "VM_KERN_MEMORY_SKYWALK",
    27: "VM_KERN_MEMORY_LTABLE",
    28: "VM_KERN_MEMORY_HV",
    29: "VM_KERN_MEMORY_KALLOC_DATA",
    30: "VM_KERN_MEMORY_RETIRED",
    31: "VM_KERN_MEMORY_KALLOC_TYPE",
    32: "VM_KERN_MEMORY_TRIAGE",
    33: "VM_KERN_MEMORY_RECOUNT",
    34: "VM_KERN_MEMORY_TAG",
    35: "VM_KERN_MEMORY_EXCLAVES",
    255:"VM_KERN_MEMORY_ANY",
}

def GetVMKernName(tag):
    """ returns the formatted name for a vmtag and
        the sub-tag for kmod tags.
    """
    if tag in FixedTags:
        return (FixedTags[tag], "")
    site = kern.globals.vm_allocation_sites[tag]
    if site:
        if site.flags & 0x007F:
            cstr = addressof(site.subtotals[site.subtotalscount])
            return ("{:<50s}".format(str(Cast(cstr, 'char *'))), "")
        else:
            if site.flags & 0x0200:
                xsite = Cast(site,'OSKextAccount *')
                tagstr = ".{:<3d}".format(xsite.loadTag)
                return (GetKmodIDName(xsite.loadTag), tagstr);
            else:
                return (kern.Symbolicate(site), "")
    return ("", "")

@SBValueFormatter.converter("vm_kern_tag")
def vm_kern_tag_conversion(tag):
    s, tagstr = GetVMKernName(tag)

    if tagstr != '':
        return "{} ({}{})".format(s.strip(), tag, tagstr)
    if s != '':
        return "{} ({})".format(s.strip(), tag)
    return str(tag)

@lldb_command("showvmtags", "ASJO")
def showvmtags(cmd_args=None, cmd_options={}):
    """Routine to print out info about kernel wired page allocations
        usage: showvmtags
               iterates kernel map and vm objects totaling allocations by tag.
        usage: showvmtags -S [-O]
               also iterates kernel object pages individually - slow.
        usage: showvmtags -A [-O]
               show all tags, even tags that have no wired count
        usage: showvmtags -J [-O]
                Output json

        -O: list in increasing size order
    """
    slow = False
    print_json = False
    if "-S" in cmd_options:
        slow = True
    all_tags = False
    if "-A" in cmd_options:
        all_tags = True
    if "-J" in cmd_options:
        print_json = True

    page_size = unsigned(kern.globals.page_size)
    nsites = unsigned(kern.globals.vm_allocation_tag_highest) + 1
    tagcounts = [0] * nsites
    tagmapped = [0] * nsites

    if kern.globals.vm_tag_active_update:
        for tag in range(nsites):
            site = kern.globals.vm_allocation_sites[tag]
            if site:
                tagcounts[tag] = unsigned(site.total)
                tagmapped[tag] = unsigned(site.mapped)
    else:
        queue_head = kern.globals.vm_objects_wired
        for object in IterateQueue(queue_head, 'struct vm_object *', 'wired_objq'):
            if object != kern.globals.kernel_object_default and ((not hasattr(kern.globals, 'kernel_object_tagged')) or object != kern.globals.kernel_object_tagged):
                CountWiredObject(object, tagcounts)

        CountMapTags(kern.globals.kernel_map, tagcounts, slow)

    total = 0
    totalmapped = 0
    tags = []
    for tag in range(nsites):
        if all_tags or tagcounts[tag] or tagmapped[tag]:
            current = {}
            total += tagcounts[tag]
            totalmapped += tagmapped[tag]
            (sitestr, tagstr) = GetVMKernName(tag)
            current["name"] = sitestr
            current["size"] = tagcounts[tag]
            current["mapped"] = tagmapped[tag]
            current["tag"] = tag
            current["tagstr"] = tagstr
            current["subtotals"] = []

            site = kern.globals.vm_allocation_sites[tag]
            for sub in range(site.subtotalscount):
                alloctag = unsigned(site.subtotals[sub].tag)
                amount = unsigned(site.subtotals[sub].total)
                subsite = kern.globals.vm_allocation_sites[alloctag]
                if alloctag and subsite:
                    (sitestr, tagstr) = GetVMKernName(alloctag)
                    current["subtotals"].append({
                        "amount": amount,
                        "flags": int(subsite.flags),
                        "tag": alloctag,
                        "tagstr": tagstr,
                        "sitestr": sitestr,
                    })
            tags.append(current)

    if "-O" in cmd_options:
        tags.sort(key = lambda tag: tag['size'])

    # Serializing to json here ensure we always catch bugs preventing
    # serialization
    as_json = json.dumps(tags)
    if print_json:
        print(as_json)
    else:
        print(" vm_allocation_tag_highest: {:<7d}  ".format(nsites - 1))
        print(" {:<7s}  {:>7s}   {:>7s}  {:<50s}".format("tag.kmod", "size", "mapped", "name"))
        for tag in tags:
            if not tagstr:
                tagstr = ""
            print(" {:>3d}{:<4s}  {:>7d}K  {:>7d}K  {:<50s}".format(tag["tag"], tag["tagstr"], tag["size"] // 1024, tag["mapped"] // 1024, tag["name"]))
            for sub in tag["subtotals"]:
                if ((sub["flags"] & 0x007f) == 0):
                    kind_str = "named"
                else:
                    kind_str = "from"

                print(" {:>7s}  {:>7d}K      {:s}  {:>3d}{:<4s} {:<50s}".format(" ", sub["amount"] // 1024, kind_str, sub["tag"], sub["tagstr"], sub["sitestr"]))

        print("Total:    {:>7d}K  {:>7d}K".format(total // 1024, totalmapped // 1024))
    return None


def FindVMEntriesForVnode(task, vn):
    """ returns an array of vme that have the vnode set to defined vnode
        each entry in array is of format (vme, start_addr, end_address, protection)
    """
    retval = []
    vmmap = task.map
    pmap = vmmap.pmap
    pager_ops_addr = unsigned(addressof(kern.globals.vnode_pager_ops))
    debuglog("pager_ops_addr %s" % hex(pager_ops_addr))

    if unsigned(pmap) == 0:
        return retval
    vme_list_head = vmmap.hdr.links
    vme_ptr_type = gettype('vm_map_entry *')
    for vme in IterateQueue(vme_list_head, vme_ptr_type, 'links'):
        #print vme
        if unsigned(vme.is_sub_map) == 0 and unsigned(get_vme_object(vme)) != 0:
            obj = get_vme_object(vme)
        else:
            continue

        while obj != 0:
            if obj.pager != 0:
                if obj.internal:
                    pass
                else:
                    vn_pager = Cast(obj.pager, 'vnode_pager *')
                    if unsigned(vn_pager.vn_pgr_hdr.mo_pager_ops) == pager_ops_addr and unsigned(vn_pager.vnode_handle) == unsigned(vn):
                        retval.append((vme, unsigned(vme.links.start), unsigned(vme.links.end), unsigned(vme.protection)))
            obj = obj.shadow
    return retval

@lldb_command('showtaskloadinfo')
def ShowTaskLoadInfo(cmd_args=None, cmd_options={}):
    """ Print the load address and uuid for the process
        Usage: (lldb)showtaskloadinfo <task_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Insufficient arguments")

    t = kern.GetValueFromAddress(cmd_args[0], 'struct task *')
    print_format = "0x{0:x} - 0x{1:x} {2: <50s} (??? - ???) <{3: <36s}> {4: <50s}"
    p = GetProcFromTask(t)
    if p is None:
        print("Task has no associated BSD process.")
        return
    uuid_out_string = GetUUIDSummary(p.p_uuid)
    filepath = GetVnodePath(p.p_textvp)
    libname = filepath.split('/')[-1]
    mappings = FindVMEntriesForVnode(t, p.p_textvp)
    load_addr = 0
    end_addr = 0
    for m in mappings:
        if m[3] == 5:
            load_addr = m[1]
            end_addr = m[2]
    print(print_format.format(load_addr, end_addr,
                              libname, uuid_out_string, filepath))

@header("{0: <20s} {1: <20s} {2: <20s}".format("vm_page_t", "offset", "object"))
@lldb_command('vmpagelookup')
def VMPageLookup(cmd_args=None):
    """ Print the pages in the page bucket corresponding to the provided object and offset.
        Usage: (lldb)vmpagelookup <vm_object_t> <vm_offset_t>
    """
    if cmd_args is None or len(cmd_args) != 2:
        raise ArgumentError("Please specify an object and offset.")

    format_string = "{0: <#020x} {1: <#020x} {2: <#020x}\n"

    obj = kern.GetValueFromAddress(cmd_args[0],'unsigned long long')
    off = kern.GetValueFromAddress(cmd_args[1],'unsigned long long')

    hash_id = _calc_vm_page_hash(obj, off)

    page_list = kern.globals.vm_page_buckets[hash_id].page_list
    print("hash_id: 0x%x page_list: 0x%x\n" % (unsigned(hash_id), unsigned(page_list)))

    print(VMPageLookup.header)
    page = _vm_page_unpack_ptr(page_list)
    while page != 0:
        pg_t = kern.GetValueFromAddress(page, 'vm_page_t')
        print(format_string.format(page, pg_t.vmp_offset, _vm_page_unpack_ptr(pg_t.vmp_object)))
        page = _vm_page_unpack_ptr(pg_t.vmp_next_m)


def _vm_page_get_phys_page(page):
    if kern.arch == 'x86_64':
        return page.vmp_phys_page

    if page == 0 :
        return 0

    m = unsigned(page)

    if m >= unsigned(kern.globals.vm_pages) and m < unsigned(kern.globals.vm_pages_end) :
        return (m - unsigned(kern.globals.vm_pages)) // sizeof('struct vm_page') + unsigned(kern.globals.vm_pages_first_pnum)

    target = LazyTarget.GetTarget()
    return target.xReadUInt32(unsigned(page) + sizeof('struct vm_page'))


@lldb_command('vmpage_get_phys_page')
def VmPageGetPhysPage(cmd_args=None):
    """ return the physical page for a vm_page_t
        usage: vm_page_get_phys_page <vm_page_t>
    """
    if cmd_args is None or len(cmd_args) != 1:
        raise ArgumentError("Missing page argument")

    target = LazyTarget.GetTarget()
    addr = ArgumentStringToAddress(cmd_args[0])
    page = target.xCreateValueFromAddress(None, addr, gettype('struct vm_page'))
    phys_page = _vm_page_get_phys_page(value(page.AddressOf()))
    print("phys_page = {:#x}".format(phys_page))


def _vm_page_get_page_from_phys(pnum):
    """ Attempt to return page struct from physical page address"""
    if kern.arch == 'x86_64':
        return None

    pmap_first_pnum     = unsigned(kern.globals.pmap_first_pnum)
    vm_pages_first_pnum = unsigned(kern.globals.vm_pages_first_pnum)
    vm_pages_count      = unsigned(kern.globals.vm_pages_count)

    if pmap_first_pnum <= pnum < vm_pages_first_pnum:
        target = LazyTarget.GetTarget()

        radix  = kern.globals.vm_pages_radix_root
        level  = unsigned(radix) & 0x7
        node   = unsigned(radix) - level
        index  = pnum - pmap_first_pnum
        unpack = kmemory.KMem.get_shared().vm_page_packing.unpack

        while node:
            key  = (index >> (8 * level)) & 0xff
            node = unpack(target.xReadUInt32(node + key * 4))
            if node and level == 0:
                name = "page_for_pnum_{:#x}".format(pnum)
                v = target.xCreateValueFromAddress(name, node, gettype('struct vm_page'))
                return value(v)
            level -= 1

        return None

    elif vm_pages_first_pnum <= pnum < vm_pages_first_pnum + vm_pages_count:
        return kern.globals.vm_pages[pnum - vm_pages_first_pnum]

    return None


@lldb_command('vmpage_from_phys_page')
def VmPageFromPhysPage(cmd_args=None):
    """ return the vm_page_t for a physical page if possible
        usage: vm_page_from_phys_page <ppnum_t>
    """

    if cmd_args is None or len(cmd_args) != 1:
        raise ArgumentError("Missing pnum argument")

    pnum = ArgumentStringToInt(cmd_args[0])
    page = _vm_page_get_page_from_phys(pnum)
    if page is None:
        print("couldn't find page for pnum = {:#x}".format(pnum))
        return

    print(xnu_format(
        "page = (vm_page_t){:#x}\n"
        "\n"
        "{:s}",
        addressof(page),
        str(page)))


@lldb_command('vmpage_unpack_ptr')
def VmPageUnpackPtr(cmd_args=None):
    """ unpack a pointer
        usage: vm_page_unpack_ptr <packed_ptr>
    """
    if cmd_args is None or len(cmd_args) == 0:
        print("Please provide valid packed pointer argument. Type help vm_page_unpack_ptr for help.")
        return

    packed = kern.GetValueFromAddress(cmd_args[0],'unsigned long')
    unpacked = _vm_page_unpack_ptr(packed)
    print("unpacked pointer = 0x%x\n" % unpacked)


def _vm_page_unpack_ptr(page: value) -> int:
    if kern.ptrsize == 4 :
        return int(page)

    if page == 0 :
        return 0

    params = kern.globals.vm_page_packing_params
    ptr_shift = params.vmpp_shift
    ptr_mask = kern.globals.vm_packed_from_vm_pages_array_mask

    # when no mask and shift on 64bit systems, we're working with real/non-packed pointers
    if ptr_shift == 0 and ptr_mask == 0:
        return int(page)

    if unsigned(page) & unsigned(ptr_mask):
        masked_page = (unsigned(page) & ~ptr_mask)
        # can't use addressof(kern.globals.vm_pages[masked_page]) due to 32 bit limitation in SB bridge
        vm_pages_addr = unsigned(addressof(kern.globals.vm_pages[0]))
        element_size = unsigned(addressof(kern.globals.vm_pages[1])) - vm_pages_addr
        return (vm_pages_addr + masked_page * element_size)

    kmem = kmemory.KMem.get_shared()
    return kmem.vm_page_packing.unpack(unsigned(page))

@lldb_command('calcvmpagehash')
def CalcVMPageHash(cmd_args=None):
    """ Get the page bucket corresponding to the provided object and offset.
        Usage: (lldb)calcvmpagehash <vm_object_t> <vm_offset_t>
    """
    if cmd_args is None or len(cmd_args) != 2:
        raise ArgumentError("Please specify an object and offset.")

    obj = kern.GetValueFromAddress(cmd_args[0],'unsigned long long')
    off = kern.GetValueFromAddress(cmd_args[1],'unsigned long long')

    hash_id = _calc_vm_page_hash(obj, off)

    print("hash_id: 0x%x page_list: 0x%x\n" % (unsigned(hash_id), unsigned(kern.globals.vm_page_buckets[hash_id].page_list)))
    return None

def _calc_vm_page_hash(obj, off):
    bucket_hash = (int) (kern.globals.vm_page_bucket_hash)
    hash_mask = (int) (kern.globals.vm_page_hash_mask)

    one = (obj * bucket_hash) & 0xFFFFFFFF
    two = off >> unsigned(kern.globals.page_shift)
    three = two ^ bucket_hash
    four = one + three
    hash_id = four & hash_mask

    return hash_id

#Macro: showallocatedzoneelement
@lldb_command('showallocatedzoneelement', fancy=True)
def ShowAllocatedElementsInZone(cmd_args=None, cmd_options={}, O=None):
    """ Show all the allocated elements in a zone
        usage: showzoneallocelements <address of zone>
    """
    if len(cmd_args) < 1:
        raise ArgumentError("Please specify a zone")

    zone  = kern.GetValueFromAddress(cmd_args[0], 'struct zone *')
    array = kern.GetGlobalVariable('zone_array')
    index = (unsigned(zone) - array.GetSBValue().GetLoadAddress()) // gettype('struct zone').GetByteSize()
    with O.table("{:<8s}  {:<s}".format("Index", "Address")):
        i = 1
        for elem in kmemory.Zone(index):
            print(O.format("{:>8d}  {:#x}", i, elem))
            i += 1

#EndMacro: showallocatedzoneelement

def match_vm_page_attributes(page, matching_attributes):
    page_ptr = addressof(page)
    unpacked_vm_object = _vm_page_unpack_ptr(page.vmp_object)
    matched_attributes = 0
    if "vmp_q_state" in matching_attributes and (page.vmp_q_state == matching_attributes["vmp_q_state"]):
        matched_attributes += 1
    if "vm_object" in matching_attributes and (unsigned(unpacked_vm_object) == unsigned(matching_attributes["vm_object"])):
        matched_attributes += 1
    if "vmp_offset" in matching_attributes and (unsigned(page.vmp_offset) == unsigned(matching_attributes["vmp_offset"])):
        matched_attributes += 1
    if "phys_page" in matching_attributes and (unsigned(_vm_page_get_phys_page(page_ptr)) == unsigned(matching_attributes["phys_page"])):
        matched_attributes += 1
    if "bitfield" in matching_attributes and unsigned(page.__getattr__(matching_attributes["bitfield"])) == 1:
        matched_attributes += 1

    return matched_attributes

#Macro scan_vm_pages
@header("{0: >26s}{1: >20s}{2: >10s}{3: >20s}{4: >20s}{5: >16s}".format("vm_pages_index/zone", "vm_page", "q_state", "vm_object", "offset", "ppn", "bitfield", "from_zone_map"))
@lldb_command('scan_vm_pages', 'S:O:F:I:P:B:I:N:ZA')
def ScanVMPages(cmd_args=None, cmd_options={}):
    """ Scan the global vm_pages array (-A) and/or vmpages zone (-Z) for pages with matching attributes.
        usage: scan_vm_pages <matching attribute(s)> [-A start vm_pages index] [-N number of pages to scan] [-Z scan vm_pages zone]

            scan_vm_pages -A: scan vm pages in the global vm_pages array
            scan_vm_pages -Z: scan vm pages allocated from the vm.pages zone
            scan_vm_pages <-A/-Z> -S <vm_page_q_state value>: Find vm pages in the specified queue
            scan_vm_pages <-A/-Z> -O <vm_object>: Find vm pages in the specified vm_object
            scan_vm_pages <-A/-Z> -F <offset>: Find vm pages with the specified vmp_offset value
            scan_vm_pages <-A/-Z> -P <phys_page>: Find vm pages with the specified physical page number
            scan_vm_pages <-A/-Z> -B <bitfield>: Find vm pages with the bitfield set
            scan_vm_pages <-A> -I <start_index>: Start the scan from start_index
            scan_vm_pages <-A> -N <npages>: Scan at most npages
    """
    if (len(cmd_options) < 1):
        raise ArgumentError("Please specify at least one matching attribute")

    vm_pages = kern.globals.vm_pages
    vm_pages_count = kern.globals.vm_pages_count

    start_index = 0
    npages = vm_pages_count
    scan_vmpages_array = False
    scan_vmpages_zone = False
    attribute_count = 0

    if "-A" in cmd_options:
        scan_vmpages_array = True

    if "-Z" in cmd_options:
        scan_vmpages_zone = True

    if not scan_vmpages_array and not scan_vmpages_zone:
        raise ArgumentError("Please specify where to scan (-A: vm_pages array, -Z: vm.pages zone)")

    attribute_values = {}
    if "-S" in cmd_options:
        attribute_values["vmp_q_state"] = kern.GetValueFromAddress(cmd_options["-S"], 'int')
        attribute_count += 1

    if "-O" in cmd_options:
        attribute_values["vm_object"] = kern.GetValueFromAddress(cmd_options["-O"], 'vm_object_t')
        attribute_count += 1

    if "-F" in cmd_options:
        attribute_values["vmp_offset"] = kern.GetValueFromAddress(cmd_options["-F"], 'unsigned long long')
        attribute_count += 1

    if "-P" in cmd_options:
        attribute_values["phys_page"] = kern.GetValueFromAddress(cmd_options["-P"], 'unsigned int')
        attribute_count += 1

    if "-B" in cmd_options:
        valid_vmp_bitfields = [
            "vmp_on_specialq",
            "vmp_canonical",
            "vmp_gobbled",
            "vmp_laundry",
            "vmp_no_cache",
            "vmp_reference",
            "vmp_busy",
            "vmp_wanted",
            "vmp_tabled",
            "vmp_hashed",
            "vmp_clustered",
            "vmp_pmapped",
            "vmp_xpmapped",
            "vmp_free_when_done",
            "vmp_absent",
            "vmp_error",
            "vmp_dirty",
            "vmp_cleaning",
            "vmp_precious",
            "vmp_overwriting",
            "vmp_restart",
            "vmp_unusual",
            "vmp_cs_validated",
            "vmp_cs_tainted",
            "vmp_cs_nx",
            "vmp_reusable",
            "vmp_lopage",
            "vmp_written_by_kernel",
            "vmp_unused_object_bits"
            ]
        attribute_values["bitfield"] = cmd_options["-B"]
        if attribute_values["bitfield"] in valid_vmp_bitfields:
            attribute_count += 1
        else:
            raise ArgumentError("Unknown bitfield: {0:>20s}".format(bitfield))

    if "-I" in cmd_options:
        start_index = kern.GetValueFromAddress(cmd_options["-I"], 'int')
        npages = vm_pages_count - start_index

    if "-N" in cmd_options:
        npages = kern.GetValueFromAddress(cmd_options["-N"], 'int')
        if npages == 0:
            raise ArgumentError("You specified -N 0, nothing to be scanned")

    end_index = start_index + npages - 1
    if end_index >= vm_pages_count:
        raise ArgumentError("Index range out of bound. vm_pages_count: {0:d}".format(vm_pages_count))

    header_after_n_lines = 40
    format_string = "{0: >26s}{1: >#20x}{2: >10d}{3: >#20x}{4: >#20x}{5: >#16x}"

    found_in_array = 0
    if scan_vmpages_array:
        print("Scanning vm_pages[{0:d} to {1:d}] for {2:d} matching attribute(s)......".format(start_index, end_index, attribute_count))
        i = start_index
        while i <= end_index:
            page = vm_pages[i]
            if match_vm_page_attributes(page, attribute_values) == attribute_count:
                if found_in_array % header_after_n_lines == 0:
                    print(ScanVMPages.header)

                print(format_string.format(str(i), addressof(page), page.vmp_q_state, _vm_page_unpack_ptr(page.vmp_object), page.vmp_offset, _vm_page_get_phys_page(addressof(page))))
                found_in_array += 1

            i += 1

    found_in_zone = 0
    if scan_vmpages_zone:
        page_size = kern.GetGlobalVariable('page_size')
        print("Scanning vm.pages zone for {0:d} matching attribute(s)......".format(attribute_count))

        print("Scanning page queues in the vm_pages zone...")
        for elem in kmemory.Zone('vm pages'):
            page = kern.GetValueFromAddress(elem, 'vm_page_t')

            if match_vm_page_attributes(page, attribute_values) == attribute_count:
                if found_in_zone % header_after_n_lines == 0:
                    print(ScanVMPages.header)

                vm_object = _vm_page_unpack_ptr(page.vmp_object)
                phys_page = _vm_page_get_phys_page(page)
                print(format_string.format("vm_pages zone", elem, page.vmp_q_state, vm_object, page.vmp_offset, phys_page))
                found_in_zone += 1

    total = found_in_array + found_in_zone
    print("Found {0:d} vm pages ({1:d} in array, {2:d} in zone) matching the requested {3:d} attribute(s)".format(total, found_in_array, found_in_zone, attribute_count))

#EndMacro scan_vm_pages

VM_PAGE_IS_WIRED = 1

@header("{0: <10s} of {1: <10s} {2: <20s} {3: <20s} {4: <20s} {5: <10s} {6: <5s}\t{7: <28s}\t{8: <50s}".format("index", "total", "vm_page_t", "offset", "next", "phys_page", "wire#", "first bitfield", "second bitfield"))
@lldb_command('vmobjectwalkpages', 'CSBNQP:O:')
def VMObjectWalkPages(cmd_args=None, cmd_options={}):
    """ Print the resident pages contained in the provided object. If a vm_page_t is provided as well, we
        specifically look for this page, highlighting it in the output or noting if it was not found. For
        each page, we confirm that it points to the object. We also keep track of the number of pages we
        see and compare this to the object's resident page count field.
        Usage:
            vmobjectwalkpages <vm_object_t> : Walk and print all the pages for a given object (up to 4K pages by default)
            vmobjectwalkpages <vm_object_t> -C : list pages in compressor after processing resident pages
            vmobjectwalkpages <vm_object_t> -B : Walk and print all the pages for a given object (up to 4K pages by default), traversing the memq backwards
            vmobjectwalkpages <vm_object_t> -N : Walk and print all the pages for a given object, ignore the page limit
            vmobjectwalkpages <vm_object_t> -Q : Walk all pages for a given object, looking for known signs of corruption (i.e. q_state == VM_PAGE_IS_WIRED && wire_count == 0)
            vmobjectwalkpages <vm_object_t> -P <vm_page_t> : Walk all the pages for a given object, annotate the specified page in the output with ***
            vmobjectwalkpages <vm_object_t> -P <vm_page_t> -S : Walk all the pages for a given object, stopping when we find the specified page
            vmobjectwalkpages <vm_object_t> -O <offset> : Like -P, but looks for given offset

    """

    if (cmd_args is None or len(cmd_args) < 1):
        raise ArgumentError("Please specify at minimum a vm_object_t and optionally a vm_page_t")

    out_string = ""

    obj = kern.GetValueFromAddress(cmd_args[0], 'vm_object_t')

    page = 0
    if "-P" in cmd_options:
        page = kern.GetValueFromAddress(cmd_options['-P'], 'vm_page_t')

    off = -1
    if "-O" in cmd_options:
        off = kern.GetValueFromAddress(cmd_options['-O'], 'vm_offset_t')

    stop = 0
    if "-S" in cmd_options:
        if page == 0 and off < 0:
            raise ArgumentError("-S can only be passed when a page is specified with -P or -O")
        stop = 1

    walk_backwards = False
    if "-B" in cmd_options:
        walk_backwards = True

    quiet_mode = False
    if "-Q" in cmd_options:
        quiet_mode = True

    if not quiet_mode:
        print(VMObjectWalkPages.header)
        format_string = "{0: <#10d} of {1: <#10d} {2: <#020x} {3: <#020x} {4: <#020x} {5: <#010x} {6: <#05d}\t"
        first_bitfield_format_string = "{0: <#2d}:{1: <#1d}:{2: <#1d}:{3: <#1d}:{4: <#1d}:{5: <#1d}:{6: <#1d}\t"
        second_bitfield_format_string = "{0: <#1d}:{1: <#1d}:{2: <#1d}:{3: <#1d}:{4: <#1d}:{5: <#1d}:{6: <#1d}:"
        second_bitfield_format_string += "{7: <#1d}:{8: <#1d}:{9: <#1d}:{10: <#1d}:{11: <#1d}:{12: <#1d}:"
        second_bitfield_format_string += "{13: <#1d}:{14: <#1d}:{15: <#1d}:{16: <#1d}:{17: <#1d}:{18: <#1d}:{19: <#1d}:"
        second_bitfield_format_string +=  "{20: <#1d}:{21: <#1d}:{22: <#1d}:{23: <#1d}:{24: <#1d}:{25: <#1d}:{26: <#1d}"

    limit = 4096 #arbitrary limit of number of pages to walk
    ignore_limit = 0
    if "-N" in cmd_options:
        ignore_limit = 1

    show_compressed = 0
    if "-C" in cmd_options:
        show_compressed = 1

    page_count = 0
    res_page_count = unsigned(obj.resident_page_count)
    page_found = False
    pages_seen = set()

    for vmp in IterateQueue(obj.memq, "vm_page_t", "vmp_listq", walk_backwards, unpack_ptr_fn=_vm_page_unpack_ptr):
        page_count += 1
        out_string = ""
        if (page != 0 and not(page_found) and vmp == page):
            out_string += "******"
            page_found = True

        if (off > 0 and not(page_found) and vmp.vmp_offset == off):
            out_string += "******"
            page_found = True

        if page != 0 or off > 0 or quiet_mode:
             if (page_count % 1000) == 0:
                print("traversed %d pages ...\n" % (page_count))
        else:
                phys_page = _vm_page_get_phys_page(vmp)
                vmp_fictitious = phys_page in (0xfffffffe, 0xffffffff)
                vmp_private = not vmp.vmp_canonical and not vmp_fictitious

                out_string += format_string.format(page_count, res_page_count, vmp, vmp.vmp_offset, _vm_page_unpack_ptr(vmp.vmp_listq.next), phys_page, vmp.vmp_wire_count)
                out_string += first_bitfield_format_string.format(vmp.vmp_q_state, vmp.vmp_on_specialq, vmp.vmp_gobbled, vmp.vmp_laundry, vmp.vmp_no_cache,
                                                                   vmp_private, vmp.vmp_reference)

                if hasattr(vmp,'slid'):
                    vmp_slid = vmp.slid
                else:
                    vmp_slid = 0
                out_string += second_bitfield_format_string.format(vmp.vmp_busy, vmp.vmp_wanted, vmp.vmp_tabled, vmp.vmp_hashed, vmp_fictitious, vmp.vmp_clustered,
                                                                    vmp.vmp_pmapped, vmp.vmp_xpmapped, vmp.vmp_wpmapped, vmp.vmp_free_when_done, vmp.vmp_absent,
                                                                    vmp.vmp_error, vmp.vmp_dirty, vmp.vmp_cleaning, vmp.vmp_precious, vmp.vmp_overwriting,
                                                                    vmp.vmp_restart, vmp.vmp_unusual, 0, 0,
                                                                    vmp.vmp_cs_validated, vmp.vmp_cs_tainted, vmp.vmp_cs_nx, vmp.vmp_reusable, vmp.vmp_lopage, vmp_slid,
                                                                    vmp.vmp_written_by_kernel)

        if (vmp in pages_seen):
            print(out_string + "cycle detected! we've seen vm_page_t: " + "{0: <#020x}".format(unsigned(vmp)) + " twice. stopping...\n")
            return

        if (_vm_page_unpack_ptr(vmp.vmp_object) != unsigned(obj)):
            print(out_string + " vm_page_t: " + "{0: <#020x}".format(unsigned(vmp)) +  " points to different vm_object_t: " + "{0: <#020x}".format(unsigned(_vm_page_unpack_ptr(vmp.vmp_object))))
            return

        if (vmp.vmp_q_state == VM_PAGE_IS_WIRED) and (vmp.vmp_wire_count == 0):
            print(out_string + " page in wired state with wire_count of 0\n")
            print("vm_page_t: " + "{0: <#020x}".format(unsigned(vmp)) + "\n")
            print("stopping...\n")
            return

        if (hasattr(vmp, 'vmp_unused_page_bits') and (vmp.vmp_unused_page_bits != 0)):
            print(out_string + " unused bits not zero for vm_page_t: " + "{0: <#020x}".format(unsigned(vmp)) + " unused__pageq_bits: %d\n" % (vmp.vmp_unused_page_bits))
            print("stopping...\n")
            return

        if (hasattr(vmp, 'vmp_unused_object_bits') and (vmp.vmp_unused_object_bits != 0)):
            print(out_string + " unused bits not zero for vm_page_t: " + "{0: <#020x}".format(unsigned(vmp)) + " unused_object_bits : %d\n" % (vmp.vmp_unused_object_bits))
            print("stopping...\n")
            return

        pages_seen.add(vmp)

        if False:
            hash_id = _calc_vm_page_hash(obj, vmp.vmp_offset)
            hash_page_list = kern.globals.vm_page_buckets[hash_id].page_list
            hash_page = _vm_page_unpack_ptr(hash_page_list)
            hash_page_t = 0

            while (hash_page != 0):
                hash_page_t = kern.GetValueFromAddress(hash_page, 'vm_page_t')
                if hash_page_t == vmp:
                    break
                hash_page = _vm_page_unpack_ptr(hash_page_t.vmp_next_m)

            if (unsigned(vmp) != unsigned(hash_page_t)):
                print(out_string + "unable to find page: " + "{0: <#020x}".format(unsigned(vmp)) + " from object in kernel page bucket list\n")
                print(lldb_run_command("vm_page_info %s 0x%x" % (cmd_args[0], unsigned(vmp.vmp_offset))))
                return

        if (page_count >= limit and not(ignore_limit)):
            print(out_string + "Limit reached (%d pages), stopping..." % (limit))
            break

        print(out_string)

        if page_found and stop:
            print("Object reports resident page count of: %d we stopped after traversing %d and finding the requested page.\n" % (unsigned(obj.res_page_count), unsigned(page_count)))
            return

    if (page != 0):
        print("page found? : %s\n" % page_found)

    if (off > 0):
        print("page found? : %s\n" % page_found)

    print("Object reports resident page count of %d, we saw %d pages when we walked the resident list.\n" % (unsigned(obj.resident_page_count), unsigned(page_count)))

    if show_compressed != 0 and obj.pager != 0 and unsigned(obj.pager.mo_pager_ops) == unsigned(addressof(kern.globals.compressor_pager_ops)):
        pager = Cast(obj.pager, 'compressor_pager *')
        chunks = pager.cpgr_num_slots // 128
        pagesize = kern.globals.page_size

        page_idx = 0
        while page_idx < pager.cpgr_num_slots:
            if chunks != 0:
                chunk = pager.cpgr_slots.cpgr_islots[page_idx // 128]
                slot = chunk[page_idx % 128]
            elif pager.cpgr_num_slots > 2:
                slot = pager.cpgr_slots.cpgr_dslots[page_idx]
            else:
                slot = pager.cpgr_slots.cpgr_eslots[page_idx]

            if slot != 0:
               print("compressed page for offset: %x slot %x\n" % ((page_idx * pagesize) - obj.paging_offset, slot))
            page_idx = page_idx + 1


@lldb_command("show_all_apple_protect_pagers")
def ShowAllAppleProtectPagers(cmd_args=None):
    """Routine to print all apple_protect pagers
        usage: show_all_apple_protect_pagers
    """
    print("{:>3s} {:<3s} {:<18s} {:>5s} {:>5s} {:>6s} {:>6s} {:<18s} {:<18s} {:<18s} {:<18s} {:<18s}\n".format("#", "#", "pager", "refs", "ready", "mapped", "cached", "object", "offset", "crypto_offset", "crypto_start", "crypto_end"))
    qhead = kern.globals.apple_protect_pager_queue
    qtype = GetType('apple_protect_pager *')
    qcnt = kern.globals.apple_protect_pager_count
    idx = 0
    for pager in IterateQueue(qhead, qtype, "pager_queue"):
        idx = idx + 1
        show_apple_protect_pager(pager, qcnt, idx)

@lldb_command("show_apple_protect_pager")
def ShowAppleProtectPager(cmd_args=None):
    """Routine to print out info about an apple_protect pager
        usage: show_apple_protect_pager <pager>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    pager = kern.GetValueFromAddress(cmd_args[0], 'apple_protect_pager_t')
    show_apple_protect_pager(pager, 1, 1)

def show_apple_protect_pager(pager, qcnt, idx):
    object = pager.backing_object
    shadow = object.shadow
    while shadow != 0:
        object = shadow
        shadow = object.shadow
    vnode_pager = Cast(object.pager,'vnode_pager *')
    filename = GetVnodePath(vnode_pager.vnode_handle)
    if hasattr(pager, "ap_pgr_hdr_ref"):
        refcnt = pager.ap_pgr_hdr_ref
    else:
        refcnt = pager.ap_pgr_hdr.mo_ref
    print("{:>3}/{:<3d} {: <#018x} {:>5d} {:>5d} {:>6d} {:>6d} {: <#018x} {:#018x} {:#018x} {:#018x} {:#018x}\n\tcrypt_info:{: <#018x} <decrypt:{: <#018x} end:{:#018x} ops:{: <#018x} refs:{:<d}>\n\tvnode:{: <#018x} {:s}\n".format(idx, qcnt, pager, refcnt, pager.is_ready, pager.is_mapped, pager.is_cached, pager.backing_object, pager.backing_offset, pager.crypto_backing_offset, pager.crypto_start, pager.crypto_end, pager.crypt_info, pager.crypt_info.page_decrypt, pager.crypt_info.crypt_end, pager.crypt_info.crypt_ops, pager.crypt_info.crypt_refcnt, vnode_pager.vnode_handle, filename))
    showvmobject(pager.backing_object, pager.backing_offset, pager.crypto_end - pager.crypto_start, show_pager_info=True, show_all_shadows=True, show_upl_info=True)

@lldb_command("show_all_shared_region_pagers")
def ShowAllSharedRegionPagers(cmd_args=None):
    """Routine to print all shared_region pagers
        usage: show_all_shared_region_pagers
    """
    print("{:>3s} {:<3s} {:<18s} {:>5s} {:>5s} {:>6s} {:<18s} {:<18s} {:<18s} {:<18s}\n".format("#", "#", "pager", "refs", "ready", "mapped", "object", "offset", "jop_key", "slide", "slide_info"))
    qhead = kern.globals.shared_region_pager_queue
    qtype = GetType('shared_region_pager *')
    qcnt = kern.globals.shared_region_pager_count
    idx = 0
    for pager in IterateQueue(qhead, qtype, "srp_queue"):
        idx = idx + 1
        show_shared_region_pager(pager, qcnt, idx)

@lldb_command("show_shared_region_pager")
def ShowSharedRegionPager(cmd_args=None):
    """Routine to print out info about a shared_region pager
        usage: show_shared_region_pager <pager>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    pager = kern.GetValueFromAddress(cmd_args[0], 'shared_region_pager_t')
    show_shared_region_pager(pager, 1, 1)

def show_shared_region_pager(pager, qcnt, idx):
    object = pager.srp_backing_object
    shadow = object.shadow
    while shadow != 0:
        object = shadow
        shadow = object.shadow
    vnode_pager = Cast(object.pager,'vnode_pager *')
    filename = GetVnodePath(vnode_pager.vnode_handle)
    if hasattr(pager, 'srp_ref_count'):
        ref_count = pager.srp_ref_count
    else:
        ref_count = pager.srp_header.mo_ref
    if hasattr(pager, 'srp_jop_key'):
        jop_key = pager.srp_jop_key
    else:
        jop_key = -1
    print("{:>3}/{:<3d} {: <#018x} {:>5d} {:>5d} {:>6d} {: <#018x} {:#018x} {:#018x} {:#018x}\n\tvnode:{: <#018x} {:s}\n".format(idx, qcnt, pager, ref_count, pager.srp_is_ready, pager.srp_is_mapped, pager.srp_backing_object, pager.srp_backing_offset, jop_key, pager.srp_slide_info.si_slide, pager.srp_slide_info, vnode_pager.vnode_handle, filename))
    showvmobject(pager.srp_backing_object, pager.srp_backing_offset, pager.srp_slide_info.si_end - pager.srp_slide_info.si_start, show_pager_info=True, show_all_shadows=True, show_upl_info=True)

@lldb_command("show_all_dyld_pagers")
def ShowAllDyldPagers(cmd_args=None):
    """Routine to print all dyld pagers
        usage: show_all_dyld_pagers
    """
    print(ShowDyldPager.header)
    qhead = kern.globals.dyld_pager_queue
    qtype = GetType('dyld_pager *')
    qcnt = kern.globals.dyld_pager_count
    idx = 0
    for pager in IterateQueue(qhead, qtype, "dyld_pager_queue"):
        idx = idx + 1
        show_dyld_pager(pager, qcnt, idx)

@header("{:>3s} {:<3s} {:<18s} {:>5s} {:>5s} {:>6s} {:<18s} {:<18s} {:<18s}\n".format("#", "#", "pager", "refs", "ready", "mapped", "object", "link_info", "link_info_size"))
@lldb_command("show_dyld_pager")
def ShowDyldPager(cmd_args=None):
    """Routine to print out info about a dyld pager
        usage: show_dyld_pager <pager>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    print(ShowDyldPager.header)
    pager = kern.GetValueFromAddress(cmd_args[0], 'dyld_pager_t')
    show_dyld_pager(pager, 1, 1)

def show_dyld_pager(pager, qcnt, idx):
    object = pager.dyld_backing_object
    shadow = object.shadow
    while shadow != 0:
        object = shadow
        shadow = object.shadow
    vnode_pager = Cast(object.pager,'vnode_pager *')
    filename = GetVnodePath(vnode_pager.vnode_handle)
    ref_count = pager.dyld_header.mo_ref
    print("{:>3d}/{:<3d} {: <#018x} {:>5d} {:>5d} {:>6d} {: <#018x} {:#018x} {:#018x}".format(idx, qcnt, pager, ref_count, pager.dyld_is_ready, pager.dyld_is_mapped, pager.dyld_backing_object, pager.dyld_link_info, pager.dyld_link_info_size))
    show_dyld_pager_regions(pager)
    print("\tvnode:{: <#018x} {:s}\n".format(vnode_pager.vnode_handle, filename))
    showvmobject(pager.dyld_backing_object, show_pager_info=True, show_all_shadows=True, show_upl_info=True)

def show_dyld_pager_regions(pager):
    """Routine to print out region info about a dyld pager
    """
    print("\tregions:")
    print("\t\t{:>3s}/{:<3s} {:<18s} {:<18s} {:<18s}".format("#", "#", "file_offset", "address", "size"))
    for idx in range(pager.dyld_num_range):
        print("\t\t{:>3d}/{:<3d} {: <#018x} {: <#018x} {: <#018x}".format(idx + 1, pager.dyld_num_range, pager.dyld_file_offset[idx], pager.dyld_address[idx], pager.dyld_size[idx]))

@lldb_command("show_console_ring")
def ShowConsoleRingData(cmd_args=None):
    """ Print console ring buffer stats and data
    """
    cr = kern.globals.console_ring
    print("console_ring = {:#018x}  buffer = {:#018x}  length = {:<5d}  used = {:<5d}  read_ptr = {:#018x}  write_ptr = {:#018x}".format(addressof(cr), cr.buffer, cr.len, cr.used, cr.read_ptr, cr.write_ptr))
    pending_data = []
    for i in range(unsigned(cr.used)):
        idx = ((unsigned(cr.read_ptr) - unsigned(cr.buffer)) + i) % unsigned(cr.len)
        pending_data.append("{:c}".format(cr.buffer[idx]))

    if pending_data:
        print("Data:")
        print("".join(pending_data))

def ShowJetsamZprintSnapshot():
    """ Helper function for the ShowJetsamSnapshot lldb command to print the last Jetsam zprint snapshot
    """
    jzs_trigger_band = kern.GetGlobalVariable('jzs_trigger_band')
    jzs_gencount = kern.GetGlobalVariable('jzs_gencount')
    jzs_names = kern.globals.jzs_names
    jzs_info = kern.globals.jzs_info

    if (unsigned(jzs_gencount) == ((1 << 64) - 1)):
        print("No jetsam zprint snapshot found\n")
        return
    print("Jetsam zprint snapshot jzs_trigger_band: {:2d}\n".format(jzs_trigger_band))

    info_hdr = "{0: >3s} {1: <30s} {2: >6s} {3: >11s}"
    info_fmt = "{0: >3d} {1: <30s} {2: >6d} {3: >11d}"

    count = kern.GetGlobalVariable('jzs_zone_cnt')

    print("Jetsam zprint snapshot: zone info for {:3d} zones when jetsam last hit band: {:2d}, jzs_gencount: {:6d}\n\n".format(count, jzs_trigger_band, jzs_gencount))
    print(info_hdr.format("",    "",   "elem", "cur"))
    print(info_hdr.format("#", "name", "size", "inuse"))
    print("-----------------------------------------------------------------------------------------------------------")
    idx = 0;
    while idx < count:
        info = dereference(Cast(addressof(jzs_info[idx]), 'mach_zone_info_t *'))
        if info.mzi_elem_size > 0:
            print(info_fmt.format(idx, jzs_names[idx].mzn_name, info.mzi_elem_size, info.mzi_count))
        idx += 1

    jzs_meminfo = kern.globals.jzs_meminfo

    count = kern.GetGlobalVariable('jzs_meminfo_cnt')
    print("\nJetsam zprint snapshot: wired memory info when jetsam last hit band: {:2d}, jzs_gencount: {:6d}\n\n".format(jzs_trigger_band, jzs_gencount))
    print(" {:<7s}  {:>7s}   {:>7s}   {:<50s}".format("tag.kmod", "peak", "size", "name"))
    print("---------------------------------------------------------------------------------------------------")
    idx = 0;
    while idx < count:
        meminfo = dereference(Cast(addressof(jzs_meminfo[idx]), 'mach_memory_info_t *'))
        peak = unsigned(meminfo.peak / 1024)
        size = unsigned(meminfo.size / 1024)
        if peak > 0:
            tag = unsigned(meminfo.tag)
            (sitestr, tagstr) = GetVMKernName(tag)
            print(" {:>3d}{:<4s}  {:>7d}K  {:>7d}K  {:<50s}".format(tag, tagstr, peak, size, sitestr))
        idx += 1

    return

# Macro: showjetsamsnapshot

@lldb_command("showjetsamsnapshot", "DA")
def ShowJetsamSnapshot(cmd_args=None, cmd_options={}):
    """ Dump entries in the jetsam snapshot table
        usage: showjetsamsnapshot [-D] [-A]
        Use -D flag to print extra physfootprint details
        Use -A flag to print all entries (regardless of valid count)
    """

    # Not shown are uuid, user_data, cpu_time

    global kern

    show_footprint_details = False
    show_all_entries = False

    if "-D" in cmd_options:
        show_footprint_details = True

    if "-A" in cmd_options:
        show_all_entries = True

    valid_count = kern.globals.memorystatus_jetsam_snapshot_count
    max_count = kern.globals.memorystatus_jetsam_snapshot_max

    if show_all_entries:
        count = max_count
    else:
        count = valid_count

    print("{:s}".format(valid_count))
    print("{:s}".format(max_count))

    if int(count) == 0:
        print("The jetsam snapshot is empty.")
        print("Use -A to force dump all entries (regardless of valid count)")
        return

    # Dumps the snapshot header info
    print(lldb_run_command('p *memorystatus_jetsam_snapshot'))

    hdr_format = "{0: >32s} {1: >5s} {2: >4s} {3: >6s} {4: >6s} {5: >20s} {6: >20s} {7: >20s} {8: >5s} {9: >10s} {10: >6s} {11: >6s} {12: >10s} {13: >15s} {14: >15s} {15: >15s}"
    if show_footprint_details:
        hdr_format += "{16: >15s} {17: >15s} {18: >12s} {19: >12s} {20: >17s} {21: >10s} {22: >13s} {23: >10s}"


    if not show_footprint_details:
        print(hdr_format.format('command', 'index', 'pri', 'cid', 'pid', 'starttime', 'killtime', 'idletime', 'kill', '#ents', 'fds', 'gen', 'state', 'footprint', 'purgeable', 'lifetimeMax'))
        print(hdr_format.format('', '', '', '', '', '(abs)', '(abs)', '(abs)', 'cause', '', '', 'Count', '', '(pages)', '(pages)', '(pages)'))
    else:
        print(hdr_format.format('command', 'index', 'pri', 'cid', 'pid', 'starttime', 'killtime', 'idletime', 'kill', '#ents', 'fds', 'gen', 'state', 'footprint', 'purgeable', 'lifetimeMax', '|| internal', 'internal_comp', 'iokit_mapped', 'purge_nonvol', 'purge_nonvol_comp', 'alt_acct', 'alt_acct_comp', 'page_table'))
        print(hdr_format.format('', '', '', '', '', '(abs)', '(abs)', '(abs)', 'cause', '', '', 'Count', '', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)'))


    entry_format = "{e.name: >32s} {index: >5d} {e.priority: >4d} {e.jse_coalition_jetsam_id: >6d} {e.pid: >6d} "\
                   "{e.jse_starttime: >20d} {e.jse_killtime: >20d} "\
                   "{e.jse_idle_delta: >20d} {e.killed: >5d} {e.jse_memory_region_count: >10d} "\
                   "{e.fds: >6d} {e.jse_gencount: >6d} {e.state: >10x} {e.pages: >15d} "\
                   "{e.purgeable_pages: >15d} {e.max_pages_lifetime: >15d}"

    if show_footprint_details:
        entry_format += "{e.jse_internal_pages: >15d} "\
                        "{e.jse_internal_compressed_pages: >15d} "\
                        "{e.jse_iokit_mapped_pages: >12d} "\
                        "{e.jse_purgeable_nonvolatile_pages: >12d} "\
                        "{e.jse_purgeable_nonvolatile_compressed_pages: >17d} "\
                        "{e.jse_alternate_accounting_pages: >10d} "\
                        "{e.jse_alternate_accounting_compressed_pages: >13d} "\
                        "{e.jse_page_table_pages: >10d}"

    snapshot_list = kern.globals.memorystatus_jetsam_snapshot.entries
    idx = 0
    while idx < count:
        current_entry = dereference(Cast(addressof(snapshot_list[idx]), 'jetsam_snapshot_entry *'))
        print(entry_format.format(index=idx, e=current_entry))
        idx +=1

    ShowJetsamZprintSnapshot()
    return

# EndMacro: showjetsamsnapshot

# Macro: showjetsambucket
@lldb_command('showjetsamband', 'J')
def ShowJetsamBand(cmd_args=[], cmd_options={}):
    """ Print the processes in a jetsam band.
        Usage: showjetsamband band_number [-J]
            -J      : Output pids as json
    """
    if cmd_args is None or len(cmd_args) != 1:
        raise ArgumentError("invalid arguments")

    print_json = "-J" in cmd_options

    bucket_number = int(cmd_args[0])
    buckets = kern.GetGlobalVariable('memstat_bucket')
    bucket = value(buckets.GetSBValue().CreateValueFromExpression(None,
        'memstat_bucket[%d]' %(bucket_number)))
    l = bucket.list

    pids = []
    if not print_json:
        print(GetProcSummary.header)
    for i in IterateTAILQ_HEAD(l, "p_memstat_list"):
        pids.append(int(i.p_pid))
        if not print_json:
            print(GetProcSummary(i))

    as_json = json.dumps(pids)
    if print_json:
        print(as_json)

# Macro: showvnodecleanblk/showvnodedirtyblk

def _GetBufSummary(buf):
    """ Get a summary of important information out of a buf_t.
    """
    initial = "(struct buf) {0: <#0x} ="

    # List all of the fields in this buf summary.
    entries = [buf.b_hash, buf.b_vnbufs, buf.b_freelist, buf.b_timestamp, buf.b_whichq,
        buf.b_flags, buf.b_lflags, buf.b_error, buf.b_bufsize, buf.b_bcount, buf.b_resid,
        buf.b_dev, buf.b_datap, buf.b_lblkno, buf.b_blkno, buf.b_iodone, buf.b_vp,
        buf.b_rcred, buf.b_wcred, buf.b_upl, buf.b_real_bp, buf.b_act, buf.b_drvdata,
        buf.b_fsprivate, buf.b_transaction, buf.b_dirtyoff, buf.b_dirtyend, buf.b_validoff,
        buf.b_validend, buf.b_redundancy_flags, buf.b_proc, buf.b_attr]

    # Join an (already decent) string representation of each field
    # with newlines and indent the region.
    joined_strs = "\n".join([str(i).rstrip() for i in entries]).replace('\n', "\n    ")

    # Add the total string representation to our title and return it.
    out_str = initial.format(int(buf)) + " {\n    " + joined_strs + "\n}\n\n"
    return out_str

def _ShowVnodeBlocks(dirty=True, cmd_args=None):
    """ Display info about all [dirty|clean] blocks in a vnode.
    """
    if cmd_args is None or len(cmd_args) == 0:
        print("Please provide a valid vnode argument.")
        return

    vnodeval = kern.GetValueFromAddress(cmd_args[0], 'vnode *')
    list_head = vnodeval.v_cleanblkhd;
    if dirty:
        list_head = vnodeval.v_dirtyblkhd

    print("Blocklist for vnode {}:".format(cmd_args[0]))

    i = 0
    for buf in IterateListEntry(list_head, 'b_hash'):
        # For each block (buf_t) in the appropriate list,
        # ask for a summary and print it.
        print("---->\nblock {}: ".format(i) + _GetBufSummary(buf))
        i += 1
    return

@lldb_command('showvnodecleanblk')
def ShowVnodeCleanBlocks(cmd_args=None):
    """ Display info about all clean blocks in a vnode.
        usage: showvnodecleanblk <address of vnode>
    """
    _ShowVnodeBlocks(False, cmd_args)

@lldb_command('showvnodedirtyblk')
def ShowVnodeDirtyBlocks(cmd_args=None):
    """ Display info about all dirty blocks in a vnode.
        usage: showvnodedirtyblk <address of vnode>
    """
    _ShowVnodeBlocks(True, cmd_args)

# EndMacro: showvnodecleanblk/showvnodedirtyblk


@lldb_command("vm_page_lookup_in_map")
def VmPageLookupInMap(cmd_args=None):
    """Lookup up a page at a virtual address in a VM map
        usage: vm_page_lookup_in_map <map> <vaddr>
    """
    if cmd_args is None or len(cmd_args) < 2:
        raise ArgumentError()

    map = kern.GetValueFromAddress(cmd_args[0], 'vm_map_t')
    vaddr = kern.GetValueFromAddress(cmd_args[1], 'vm_map_offset_t')
    print("vaddr {:#018x} in map {: <#018x}".format(vaddr, map))
    vm_page_lookup_in_map(map, vaddr)

def vm_page_lookup_in_map(map, vaddr):
    vaddr = unsigned(vaddr)
    vme_list_head = map.hdr.links
    vme_ptr_type = GetType('vm_map_entry *')
    for vme in IterateQueue(vme_list_head, vme_ptr_type, "links"):
        if unsigned(vme.links.start) > vaddr:
            break
        if unsigned(vme.links.end) <= vaddr:
            continue
        offset_in_vme = vaddr - unsigned(vme.links.start)
        print("  offset {:#018x} in map entry {: <#018x} [{:#018x}:{:#018x}] object {: <#018x} offset {:#018x}".format(offset_in_vme, vme, unsigned(vme.links.start), unsigned(vme.links.end), get_vme_object(vme), get_vme_offset(vme)))
        offset_in_object = offset_in_vme + get_vme_offset(vme)
        obj_or_submap = get_vme_object(vme)
        if vme.is_sub_map:
            print("vaddr {:#018x} in map {: <#018x}".format(offset_in_object, obj_or_submap))
            return vm_page_lookup_in_map(obj_or_submap, offset_in_object)
        else:
            return vm_page_lookup_in_object(obj_or_submap, offset_in_object)

@lldb_command("vm_page_lookup_in_object")
def VmPageLookupInObject(cmd_args=None):
    """Lookup up a page at a given offset in a VM object
        usage: vm_page_lookup_in_object <object> <offset>
    """
    if cmd_args is None or len(cmd_args) < 2:
        raise ArgumentError()

    object = kern.GetValueFromAddress(cmd_args[0], 'vm_object_t')
    offset = kern.GetValueFromAddress(cmd_args[1], 'vm_object_offset_t')
    print("offset {:#018x} in object {: <#018x}".format(offset, object))
    vm_page_lookup_in_object(object, offset)

def vm_page_lookup_in_object(object, offset):
    offset = unsigned(offset)
    page_size = kern.globals.page_size
    trunc_offset = offset & ~(page_size - 1)
    print("    offset {:#018x} in VM object {: <#018x}".format(offset, object))
    hash_id = _calc_vm_page_hash(object, trunc_offset)
    page_list = kern.globals.vm_page_buckets[hash_id].page_list
    page = _vm_page_unpack_ptr(page_list)
    while page != 0:
        m = kern.GetValueFromAddress(page, 'vm_page_t')
        m_object_val = _vm_page_unpack_ptr(m.vmp_object)
        m_object = kern.GetValueFromAddress(m_object_val, 'vm_object_t')
        if unsigned(m_object) != unsigned(object) or unsigned(m.vmp_offset) != unsigned(trunc_offset):
            page = _vm_page_unpack_ptr(m.vmp_next_m)
            continue
        print("    resident page {: <#018x} phys {:#010x}".format(m, _vm_page_get_phys_page(m)))
        return m
    if object.pager and object.pager_ready:
        offset_in_pager = trunc_offset + unsigned(object.paging_offset)
        if not object.internal:
            print("    offset {:#018x} in external '{:s}' {: <#018x}".format(offset_in_pager, object.pager.mo_pager_ops.memory_object_pager_name, object.pager))
            return None
        pager = Cast(object.pager, 'compressor_pager *')
        ret = vm_page_lookup_in_compressor_pager(pager, offset_in_pager)
        if ret:
            return None
    if object.shadow and not object.phys_contiguous:
        offset_in_shadow = offset + unsigned(object.vo_un2.vou_shadow_offset)
        vm_page_lookup_in_object(object.shadow, offset_in_shadow)
        return None
    print("    page is absent and will be zero-filled on demand")
    return None

@lldb_command("vm_page_lookup_in_compressor_pager")
def VmPageLookupInCompressorPager(cmd_args=None):
    """Lookup up a page at a given offset in a compressor pager
        usage: vm_page_lookup_in_compressor_pager <pager> <offset>
    """
    if cmd_args is None or len(cmd_args) < 2:
        raise ArgumentError()

    pager = kern.GetValueFromAddress(cmd_args[0], 'compressor_pager_t')
    offset = kern.GetValueFromAddress(cmd_args[1], 'memory_object_offset_t')
    print("offset {:#018x} in compressor pager {: <#018x}".format(offset, pager))
    vm_page_lookup_in_compressor_pager(pager, offset)

def vm_page_lookup_in_compressor_pager(pager, offset):
    offset = unsigned(offset)
    page_size = unsigned(kern.globals.page_size)
    page_num = unsigned(offset // page_size)
    if page_num > pager.cpgr_num_slots:
        print("      *** ERROR: vm_page_lookup_in_compressor_pager({: <#018x},{:#018x}): page_num {:#x} > num_slots {:#x}".format(pager, offset, page_num, pager.cpgr_num_slots))
        return 0
    slots_per_chunk = 512 // sizeof ('compressor_slot_t')
    num_chunks = unsigned((pager.cpgr_num_slots+slots_per_chunk-1) // slots_per_chunk)
    if num_chunks > 1:
        chunk_idx = unsigned(page_num // slots_per_chunk)
        chunk = pager.cpgr_slots.cpgr_islots[chunk_idx]
        slot_idx = unsigned(page_num % slots_per_chunk)
        slot = GetObjectAtIndexFromArray(chunk, slot_idx)
        slot_str = "islots[{:d}][{:d}]".format(chunk_idx, slot_idx)
    elif pager.cpgr_num_slots > 2:
        slot_idx = page_num
        slot = GetObjectAtIndexFromArray(pager.cpgr_slots.cpgr_dslots, slot_idx)
        slot_str = "dslots[{:d}]".format(slot_idx)
    else:
        slot_idx = page_num
        slot = GetObjectAtIndexFromArray(pager.cpgr_slots.cpgr_eslots, slot_idx)
        slot_str = "eslots[{:d}]".format(slot_idx)
    print("      offset {:#018x} in compressor pager {: <#018x} {:s} slot {: <#018x}".format(offset, pager, slot_str, slot))
    if slot == 0:
        return 0
    slot_value = dereference(slot)
    print(" value {:#010x}".format(slot_value))
    vm_page_lookup_in_compressor(Cast(slot, 'c_slot_mapping_t'))
    return 1

@lldb_command("vm_page_lookup_in_compressor")
def VmPageLookupInCompressor(cmd_args=None):
    """Lookup up a page in a given compressor slot
        usage: vm_page_lookup_in_compressor <slot>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    slot = kern.GetValueFromAddress(cmd_args[0], 'compressor_slot_t *')
    print("compressor slot {: <#018x}".format(slot))
    vm_page_lookup_in_compressor(slot)

C_SV_CSEG_ID = ((1 << 22) - 1)

def vm_page_lookup_in_compressor(slot_ptr):
    slot_ptr = Cast(slot_ptr, 'compressor_slot_t *')
    slot_value = dereference(slot_ptr)
    slot = Cast(slot_value, 'c_slot_mapping')
    print(slot)
    print("compressor slot {: <#018x} -> {:#010x} cseg {:d} cindx {:d}".format(unsigned(slot_ptr), unsigned(slot_value), slot.s_cseg, slot.s_cindx))
    if slot_ptr == 0:
        return
    if slot.s_cseg == C_SV_CSEG_ID:
        sv = kern.globals.c_segment_sv_hash_table
        print("single value[{:#d}]: ref {:d} value {:#010x}".format(slot.s_cindx, sv[slot.s_cindx].c_sv_he_un.c_sv_he.c_sv_he_ref, sv[slot.s_cindx].c_sv_he_un.c_sv_he.c_sv_he_data))
        return
    if slot.s_cseg == 0 or unsigned(slot.s_cseg) > unsigned(kern.globals.c_segments_available):
        print("*** ERROR: s_cseg {:d} is out of bounds (1 - {:d})".format(slot.s_cseg, unsigned(kern.globals.c_segments_available)))
        return
    c_segments = kern.globals.c_segments
    c_segments_elt = GetObjectAtIndexFromArray(c_segments, slot.s_cseg-1)
    c_seg = c_segments_elt.c_seg
    c_no_data = 0
    if hasattr(c_seg, 'c_state'):
        c_state = c_seg.c_state
        if c_state == 0:
            c_state_str = "C_IS_EMPTY"
            c_no_data = 1
        elif c_state == 1:
            c_state_str = "C_IS_FREE"
            c_no_data = 1
        elif c_state == 2:
            c_state_str = "C_IS_FILLING"
        elif c_state == 3:
            c_state_str = "C_ON_AGE_Q"
        elif c_state == 4:
            c_state_str = "C_ON_SWAPOUT_Q"
        elif c_state == 5:
            c_state_str = "C_ON_SWAPPEDOUT_Q"
            c_no_data = 1
        elif c_state == 6:
            c_state_str = "C_ON_SWAPPEDOUTSPARSE_Q"
            c_no_data = 1
        elif c_state == 7:
            c_state_str = "C_ON_SWAPPEDIN_Q"
        elif c_state == 8:
            c_state_str = "C_ON_MAJORCOMPACT_Q"
        elif c_state == 9:
            c_state_str = "C_ON_BAD_Q"
            c_no_data = 1
        else:
            c_state_str = "<unknown>"
    else:
        c_state = -1
        c_state_str = "<no c_state field>"
    print("c_segments[{:d}] {: <#018x} c_seg {: <#018x} c_state {:#x}={:s}".format(slot.s_cseg-1, c_segments_elt, c_seg, c_state, c_state_str))
    c_indx = unsigned(slot.s_cindx)
    if hasattr(c_seg, 'c_slot_var_array'):
        c_seg_fixed_array_len = kern.globals.c_seg_fixed_array_len
        if c_indx < c_seg_fixed_array_len:
            cs = c_seg.c_slot_fixed_array[c_indx]
        else:
            cs = GetObjectAtIndexFromArray(c_seg.c_slot_var_array, c_indx - c_seg_fixed_array_len)
    else:
        C_SEG_SLOT_ARRAY_SIZE = 64
        C_SEG_SLOT_ARRAY_MASK = C_SEG_SLOT_ARRAY_SIZE - 1
        cs = GetObjectAtIndexFromArray(c_seg.c_slots[c_indx // C_SEG_SLOT_ARRAY_SIZE], c_indx & C_SEG_SLOT_ARRAY_MASK)
    print(cs)
    kmem = kmemory.KMem.get_shared()
    c_slot_unpacked_ptr = kmem.c_slot_packing.unpack(unsigned(cs.c_packed_ptr))
    print("c_slot {: <#018x} c_offset {:#x} c_size {:#x} c_packed_ptr {:#x} (unpacked: {: <#018x})".format(cs, cs.c_offset, cs.c_size, cs.c_packed_ptr, unsigned(c_slot_unpacked_ptr)))
    if unsigned(slot_ptr) != unsigned(c_slot_unpacked_ptr):
        print("*** ERROR: compressor slot {: <#018x} points back to {: <#018x} instead of itself".format(slot_ptr, c_slot_unpacked_ptr))
    if c_no_data == 0:
        c_data = c_seg.c_store.c_buffer + (4 * cs.c_offset)
        c_size = cs.c_size
        cmd = "memory read {: <#018x} {: <#018x} --force".format(c_data, c_data + c_size)
        print(cmd)
        print(lldb_run_command(cmd))
    else:
        print("<no compressed data>")

# From vm_page.h
VM_PAGE_NOT_ON_Q = 0
VM_PAGE_IS_WIRED = 1
VM_PAGE_USED_BY_COMPRESSOR = 2
VM_PAGE_ON_FREE_Q = 3
VM_PAGE_ON_FREE_LOCAL_Q = 4
VM_PAGE_ON_FREE_LOPAGE_Q = 5
VM_PAGE_ON_THROTTLED_Q = 6
VM_PAGE_ON_PAGEOUT_Q = 7
VM_PAGE_ON_SPECULATIVE_Q = 8
VM_PAGE_ON_ACTIVE_LOCAL_Q = 9
VM_PAGE_ON_ACTIVE_Q = 10
VM_PAGE_ON_INACTIVE_INTERNAL_Q = 11
VM_PAGE_ON_INACTIVE_EXTERNAL_Q = 12
VM_PAGE_ON_INACTIVE_CLEANED_Q = 13
VM_PAGE_ON_SECLUDED_Q = 14

@lldb_command('vm_scan_all_pages')
def VMScanAllPages(cmd_args=None):
    """Scans the vm_pages[] array
    """
    vm_pages_count = kern.globals.vm_pages_count
    vm_pages = kern.globals.vm_pages

    free_count = 0
    local_free_count = 0
    active_count = 0
    local_active_count = 0
    inactive_count = 0
    speculative_count = 0
    throttled_count = 0
    wired_count = 0
    compressor_count = 0
    pageable_internal_count = 0
    pageable_external_count = 0
    secluded_count = 0
    secluded_free_count = 0
    secluded_inuse_count = 0

    i = 0
    for i in range(vm_pages_count):
        if i % 10000 == 0:
            print("{:d}/{:d}...\n".format(i,vm_pages_count))

        m = vm_pages[i]
        internal = False

        m_object_addr = _vm_page_unpack_ptr(m.vmp_object)
        if m_object_addr != 0 and (m_object := kern.CreateValueFromAddress(m_object_addr, "struct vm_object")).GetSBValue().IsValid() and m_object.internal:
            internal = True

        m_vmp_q_state = int(m.vmp_q_state)
        if m.vmp_wire_count != 0 and m_vmp_q_state != VM_PAGE_ON_ACTIVE_LOCAL_Q:
            wired_count = wired_count + 1
            pageable = 0
        elif m_vmp_q_state == VM_PAGE_ON_THROTTLED_Q:
            throttled_count = throttled_count + 1
            pageable = 0
        elif m_vmp_q_state == VM_PAGE_ON_ACTIVE_Q:
            active_count = active_count + 1
            pageable = 1
        elif m_vmp_q_state == VM_PAGE_ON_ACTIVE_LOCAL_Q:
            local_active_count = local_active_count + 1
            pageable = 0
        elif m_vmp_q_state in (VM_PAGE_ON_INACTIVE_CLEANED_Q, VM_PAGE_ON_INACTIVE_INTERNAL_Q,
                               VM_PAGE_ON_INACTIVE_EXTERNAL_Q):
            inactive_count = inactive_count + 1
            pageable = 1
        elif m_vmp_q_state == VM_PAGE_ON_SPECULATIVE_Q:
            speculative_count = speculative_count + 1
            pageable = 0
        elif m_vmp_q_state == VM_PAGE_ON_FREE_Q:
            free_count = free_count + 1
            pageable = 0
        elif m_vmp_q_state == VM_PAGE_ON_SECLUDED_Q:
            secluded_count = secluded_count + 1
            if m_object_addr == 0:
                secluded_free_count = secluded_free_count + 1
            else:
                secluded_inuse_count = secluded_inuse_count + 1
            pageable = 0
        elif m_object_addr == 0 and m.vmp_busy:
            local_free_count = local_free_count + 1
            pageable = 0
        elif m_vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR:
            compressor_count = compressor_count + 1
            pageable = 0
        else:
            print("weird page vm_pages[{:d}]?\n".format(i))
            pageable = 0

        if pageable:
            if internal:
                pageable_internal_count = pageable_internal_count + 1
            else:
                pageable_external_count = pageable_external_count + 1

    print("vm_pages_count = {:d}\n".format(vm_pages_count))

    print("wired_count = {:d}\n".format(wired_count))
    print("throttled_count = {:d}\n".format(throttled_count))
    print("active_count = {:d}\n".format(active_count))
    print("local_active_count = {:d}\n".format(local_active_count))
    print("inactive_count = {:d}\n".format(inactive_count))
    print("speculative_count = {:d}\n".format(speculative_count))
    print("free_count = {:d}\n".format(free_count))
    print("local_free_count = {:d}\n".format(local_free_count))
    print("compressor_count = {:d}\n".format(compressor_count))

    print("pageable_internal_count = {:d}\n".format(pageable_internal_count))
    print("pageable_external_count = {:d}\n".format(pageable_external_count))
    print("secluded_count = {:d}\n".format(secluded_count))
    print("secluded_free_count = {:d}\n".format(secluded_free_count))
    print("secluded_inuse_count = {:d}\n".format(secluded_inuse_count))


@lldb_command('show_all_vm_named_entries')
def ShowAllVMNamedEntries(cmd_args=None):
    """ Routine to print a summary listing of all the VM named entries
    """

    kmem = kmemory.KMem.get_shared()
    ikot_named_entry = GetEnumValue('ipc_kotype_t', 'IKOT_NAMED_ENTRY')

    port_ty = gettype('struct ipc_port')
    ent_ty  = gettype('struct vm_named_entry')

    named_entries = (
        port
        for port
        in kmemory.Zone("ipc ports").iter_allocated(port_ty)
        if port.xGetScalarByPath(".ip_object.io_bits") & 0x3ff == ikot_named_entry
    )

    for idx, port in enumerate(named_entries):
        ko  = kmem.make_address(port.xGetScalarByName('ip_kobject'))
        ent = port.xCreateValueFromAddress(None, ko, ent_ty)
        showmemoryentry(value(ent.AddressOf()), idx=idx + 1, port=value(port.AddressOf()))

@lldb_command('show_vm_named_entry')
def ShowVMNamedEntry(cmd_args=None):
    """ Routine to print a VM named entry
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    named_entry = kern.GetValueFromAddress(cmd_args[0], 'vm_named_entry_t')
    showmemoryentry(named_entry)

def showmemoryentry(entry, idx=0, port=None):
    """  Routine to print out a summary a VM memory entry
        params: 
            entry - core.value : a object of type 'struct vm_named_entry *'
        returns:
            None
    """
    show_pager_info = True
    show_all_shadows = True

    backing = ""
    if entry.is_sub_map == 1:
        backing += "SUBMAP"
    if entry.is_copy == 1:
        backing += "COPY"
    if entry.is_object == 1:
        backing += "OBJECT"
    if entry.is_sub_map == 0 and entry.is_copy == 0 and entry.is_object == 0:
        backing += "***?***"
    prot=""
    if entry.protection & 0x1:
        prot += "r"
    else:
        prot += "-"
    if entry.protection & 0x2:
        prot += "w"
    else:
        prot += "-"
    if entry.protection & 0x4:
        prot += "x"
    else:
        prot += "-"
    extra_str = ""
    if port is not None:
        extra_str += " port={:#016x}".format(port)
    print("{:d} {: <#018x} prot={:d}/{:s} type={:s} backing={: <#018x} offset={:#016x} dataoffset={:#016x} size={:#016x}{:s}".format(idx,entry,entry.protection,prot,backing,entry.backing.copy,entry.offset,entry.data_offset,entry.size,extra_str))

    if entry.is_sub_map == 1:
        showmapvme(entry.backing.map, 0, 0, show_pager_info, show_all_shadows)
    elif entry.is_copy == 1:
        showmapcopyvme(entry.backing.copy, 0, 0, show_pager_info, show_all_shadows)
    elif entry.is_object == 1:
        showmapcopyvme(entry.backing.copy, 0, 0, show_pager_info, show_all_shadows)
    else:
        print("***** UNKNOWN TYPE *****")
    print()

@lldb_command("showmaprb")
def ShowMapRB(cmd_args=None):
    """Routine to print out a VM map's RB tree
        usage: showmaprb <vm_map>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()


    map_val = kern.GetValueFromAddress(cmd_args[0], 'vm_map_t')
    print(GetVMMapSummary.header)
    print(GetVMMapSummary(map_val))

    vme_type = gettype('struct vm_map_entry')
    to_entry = vme_type.xContainerOfTransform('store')

    print(GetVMEntrySummary.header)
    for links in iter_RB_HEAD(map_val.hdr.rb_head_store.GetSBValue(), 'entry'):
        print(GetVMEntrySummary(value(to_entry(links).AddressOf())))
    return None

@lldb_command('show_all_owned_objects', 'T')
def ShowAllOwnedObjects(cmd_args=None, cmd_options={}):
    """ Routine to print the list of VM objects owned by each task
        -T: show only ledger-tagged objects
    """
    showonlytagged = False
    if "-T" in cmd_options:
        showonlytagged = True
    for task in kern.tasks:
        ShowTaskOwnedVmObjects(task, showonlytagged)

@lldb_command('show_task_owned_objects', 'T')
def ShowTaskOwnedObjects(cmd_args=None, cmd_options={}):
    """ Routine to print the list of VM objects owned by the specified task
        -T: show only ledger-tagged objects
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    showonlytagged = False
    if "-T" in cmd_options:
        showonlytagged = True
    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    ShowTaskOwnedVmObjects(task, showonlytagged)

@lldb_command('showdeviceinfo', 'J')
def ShowDeviceInfo(cmd_args=None, cmd_options={}):
    """ Routine to show basic device information (model, build, ncpus, etc...)
        Usage: memstats  [-J]
            -J      : Output json
    """
    print_json = False
    if "-J" in cmd_options:
        print_json = True
    device_info = {}
    device_info["build"] =  str(kern.globals.osversion)
    device_info["memoryConfig"] = int(kern.globals.max_mem_actual)
    device_info["ncpu"] = int(kern.globals.ncpu)
    device_info["pagesize"] = int(kern.globals.page_size)
    device_info["mlockLimit"] = signed(kern.globals.vm_global_user_wire_limit)
    # Serializing to json here ensure we always catch bugs preventing
    # serialization
    as_json = json.dumps(device_info)


    if print_json:
        print(as_json)
    else:
        PrettyPrintDictionary(device_info)

def ShowTaskOwnedVmObjects(task, showonlytagged=False):
    """  Routine to print out a summary listing of all the entries in a vm_map
        params:
            task - core.value : a object of type 'task *'
        returns:
            None
    """
    taskobjq_total = lambda:None
    taskobjq_total.objects = 0
    taskobjq_total.vsize = 0
    taskobjq_total.rsize = 0
    taskobjq_total.wsize = 0
    taskobjq_total.csize = 0
    vmo_list_head = task.task_objq
    vmo_ptr_type = GetType('vm_object *')
    idx = 0
    for vmo in IterateQueue(vmo_list_head, vmo_ptr_type, "task_objq"):
        idx += 1
        if not showonlytagged or vmo.vo_ledger_tag != 0:
            if taskobjq_total.objects == 0:
                print(' \n')
                print(GetTaskSummary.header + ' ' + GetProcSummary.header)
                print(GetTaskSummary(task) + ' ' + GetProcSummary(GetProcFromTask(task)))
                print('{:>6s} {:<6s} {:18s} {:1s} {:>6s} {:>16s} {:>10s} {:>10s} {:>10s} {:>2s} {:18s} {:>6s} {:<20s}\n'.format("#","#","object","P","refcnt","size (pages)","resid","wired","compressed","tg","owner","pid","process"))
            ShowOwnedVmObject(vmo, idx, 0, taskobjq_total)
    if taskobjq_total.objects != 0:
        print("           total:{:<10d}  [ virtual:{:<10d}  resident:{:<10d}  wired:{:<10d}  compressed:{:<10d} ]\n".format(taskobjq_total.objects, taskobjq_total.vsize, taskobjq_total.rsize, taskobjq_total.wsize, taskobjq_total.csize))
    return None

def ShowOwnedVmObject(object, idx, queue_len, taskobjq_total):
    """  Routine to print out a VM object owned by a task
        params:
            object - core.value : a object of type 'struct vm_object *'
        returns:
            None
    """
    page_size = kern.globals.page_size
    if object.purgable == 0:
        purgable = "N"
    elif object.purgable == 1:
        purgable = "V"
    elif object.purgable == 2:
        purgable = "E"
    elif object.purgable == 3:
        purgable = "D"
    else:
        purgable = "?"
    if object.pager == 0:
        compressed_count = 0
    else:
        compressor_pager = Cast(object.pager, 'compressor_pager *')
        compressed_count = compressor_pager.cpgr_num_slots_occupied

    print("{:>6d}/{:<6d} {: <#018x} {:1s} {:>6d} {:>16d} {:>10d} {:>10d} {:>10d} {:>2d} {: <#018x} {:>6d} {:<20s}\n".format(idx,queue_len,object,purgable,object.ref_count,object.vo_un1.vou_size // page_size,object.resident_page_count,object.wired_page_count,compressed_count, object.vo_ledger_tag, object.vo_un2.vou_owner,GetProcPIDForObjectOwner(object.vo_un2.vou_owner),GetProcNameForObjectOwner(object.vo_un2.vou_owner)))

    taskobjq_total.objects += 1
    taskobjq_total.vsize += object.vo_un1.vou_size // page_size
    taskobjq_total.rsize += object.resident_page_count
    taskobjq_total.wsize += object.wired_page_count
    taskobjq_total.csize += compressed_count

def GetProcPIDForObjectOwner(owner):
    """ same as GetProcPIDForTask() but deals with -1 for a disowned object
    """
    if unsigned(Cast(owner, 'int')) == unsigned(int(0xffffffff)):
        return -1
    return GetProcPIDForTask(owner)

def GetProcNameForObjectOwner(owner):
    """ same as GetProcNameForTask() but deals with -1 for a disowned object
    """
    if unsigned(Cast(owner, 'int')) == unsigned(int(0xffffffff)):
        return "<disowned>"
    return GetProcNameForTask(owner)

def GetDescForNamedEntry(mem_entry):
    out_str = "\n"
    out_str += "\t\tmem_entry {:#08x} ref:{:d} offset:{:#08x} size:{:#08x} prot{:d} backing {:#08x}".format(mem_entry, mem_entry.ref_count, mem_entry.offset, mem_entry.size, mem_entry.protection, mem_entry.backing.copy)
    if mem_entry.is_sub_map:
        out_str += " is_sub_map"
    elif mem_entry.is_copy:
        out_str += " is_copy"
    elif mem_entry.is_object:
        out_str += " is_object"
    else:
        out_str += " ???"
    return out_str

# Macro: showdiagmemthresholds
def GetDiagThresholdConvertSizeToString(size,human_readable):
    if human_readable == 1 :
        if(size > (1 << 20)) :
            return "{0: >7,.2f}MB".format(size / (1 << 20))
        elif(size > (1 << 10)) :
            return "{0: >7,.2f}KB".format(size / (1 << 10))
        return "{0: >7,.2f}B".format(float(size))
    else :
            return "{0: >9d}B".format(size )

@header("{: >8s} {: >14s}   {: >14s}   {: >10s}   {: >14s}   {: >10s}   {: >10s}  {: <32s}".format(
'PID',     'Footprint',
'Limit', 'Lim Warned','Threshold', 'Thr Warned','Thr Enabled','Command'))
def GetDiagThresholdStatusNode(proc_val,interested_pid,show_all,human_readable):
    """ Internal function to get memorystatus information from the given proc
        params: proc - value representing struct proc *
        return: str - formatted output information for proc object

        Options are 
          -p Define a pid to show information
          -a Print all the processes, regardless if threshold is enabled
          -r Show data in human readable format
    """

    if interested_pid != -1 and int(interested_pid) != int(GetProcPID(proc_val)) :
        return ""


    LF_ENTRY_ACTIVE        = 0x0001 # entry is active if set 
    LF_WAKE_NEEDED         = 0x0100  # one or more threads are asleep 
    LF_WAKE_INPROGRESS     = 0x0200  # the wait queue is being processed 
    LF_REFILL_SCHEDULED    = 0x0400  # a refill timer has been set 
    LF_REFILL_INPROGRESS   = 0x0800  # the ledger is being refilled 
    LF_CALLED_BACK         = 0x1000  # callback was called for balance in deficit 
    LF_WARNED              = 0x2000  # callback was called for balance warning 
    LF_TRACKING_MAX        = 0x4000  # track max balance. Exclusive w.r.t refill 
    LF_PANIC_ON_NEGATIVE   = 0x8000  # panic if it goes negative 
    LF_TRACK_CREDIT_ONLY   = 0x10000 # only update "credit" 
    LF_DIAG_WARNED         = 0x20000 # callback was called for balance diag 
    LF_DIAG_DISABLED       = 0x40000 # diagnostics threshold are disabled at the moment 

    out_str = ''
    task_val = GetTaskFromProc(proc_val)
    if task_val is None:
        return out_str

    task_ledgerp = task_val.ledger
    ledger_template = kern.globals.task_ledger_template

    task_phys_footprint_ledger_entry = GetLedgerEntryWithName(ledger_template, task_ledgerp, 'phys_footprint')

    diagmem_threshold = task_phys_footprint_ledger_entry['diag_threshold_scaled'] 
    if diagmem_threshold == -1 and show_all == 0 and interested_pid == -1 : 
        return ""

    diagmem_threshold_warned = task_phys_footprint_ledger_entry['flags'] & LF_DIAG_WARNED
    diagmem_threshold_disabled = task_phys_footprint_ledger_entry['flags'] & LF_DIAG_DISABLED

    phys_footprint_limit = task_phys_footprint_ledger_entry['limit']
    phys_footprint_limit_warned = task_phys_footprint_ledger_entry['flags'] & LF_WARNED
    task_mem_footprint = task_phys_footprint_ledger_entry['balance'] 


    if phys_footprint_limit_warned == 0 :
        phys_footprint_limit_warned_str = "Not warned"
    else :
        phys_footprint_limit_warned_str = "Warned"

    if diagmem_threshold_warned == 0 :
        diagmem_threshold_warned_str = "Not warned"
    else :
        diagmem_threshold_warned_str = "Warned"

    if diagmem_threshold_disabled == 0 :
        diagmem_threshold_disabled_str = "Enabled"
    else :
        diagmem_threshold_disabled_str = "Disabled"
    
    if diagmem_threshold == -1 :
        diagmem_threshold_str = "Not set"
    else :
        diagmem_threshold_str = GetDiagThresholdConvertSizeToString(diagmem_threshold * (1<<20),human_readable)
    #                  PID       FP       LIM      LIMW        THR       THRW    THRD        Name
    format_string = '{0: >8d} {1: >14s}   {2: >14s}   {3: >10s}   {4: >14s}   {5: >10s}   {6: >10s}  {7: <32s}'
    out_str += format_string.format(
        GetProcPID(proc_val), 
        GetDiagThresholdConvertSizeToString(task_mem_footprint,human_readable),
        GetDiagThresholdConvertSizeToString(phys_footprint_limit,human_readable),
        phys_footprint_limit_warned_str,
        diagmem_threshold_str,
        diagmem_threshold_warned_str,
        diagmem_threshold_disabled_str,
        GetProcName(proc_val)
        )
    return out_str

@lldb_command('showdiagmemthresholds','P:AR')
def ShowDiagmemThresholds(cmd_args=None, cmd_options={}):
    """  Routine to display each entry in diagmem threshold and its ledger related information
         Usage: showdiagmemthresholds
        Options are 
          -P Define a pid to show information
          -A Print all the processes, regardless if threshold is enabled
          -R Show data in human readable format
    """
    # If we are focusing only on one PID, lets check
    if "-P" in cmd_options:
        interested_pid = cmd_options["-P"]
    else :
        interested_pid = -1
    

    if "-A" in cmd_options:
        show_all = 1
    else :
        show_all = 0
    
    if "-R" in cmd_options:
        human_readable = 1
    else :
        human_readable = 0

    bucket_index = 0
    bucket_count = 20
    print(GetDiagThresholdStatusNode.header)
    while bucket_index < bucket_count:
        current_bucket = kern.globals.memstat_bucket[bucket_index]
        current_list = current_bucket.list
        current_proc = Cast(current_list.tqh_first, 'proc *')
        while unsigned(current_proc) != 0:
            current_line = GetDiagThresholdStatusNode(current_proc,interested_pid,show_all,human_readable)
            if current_line != "" :
                print(current_line)
            current_proc = current_proc.p_memstat_list.tqe_next
        bucket_index += 1
    print("\n\n")

    # EndMacro: showdiagmemthresholds

