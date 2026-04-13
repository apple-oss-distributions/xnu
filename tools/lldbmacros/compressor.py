'''
Macros pertaining to the VM Compressor
'''
'''
Copyright (c) 2025 Apple Inc. All rights reserved.

@APPLE_OSREFERENCE_LICENSE_HEADER_START@

This file contains Original Code and/or Modifications of Original Code
as defined in and that are subject to the Apple Public Source License
Version 2.0 (the 'License'). You may not use this file except in
compliance with the License. The rights granted to you under the License
may not be used to create, or enable the creation or redistribution of,
unlawful or unlicensed copies of an Apple operating system, or to
circumvent, violate, or enable the circumvention or violation of, any
terms of an Apple operating system software license agreement.

Please obtain a copy of the License at
http://www.opensource.apple.com/apsl/ and read it before using this file.

The Original Code and all software distributed under the License are
distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
Please see the License for the specific language governing rights and
limitations under the License.

@APPLE_OSREFERENCE_LICENSE_HEADER_END@
'''
from collections import namedtuple
from core.cvalue import addressof, gettype, sizeof, value
from core.kernelcore import IterateQueue
from datetime import timedelta
from enum import Enum
from scheduler import GetRecentTimestamp
from typing import Iterable, Optional
from utils import GetEnumName
from xnu import GetObjectAtIndexFromArray, header, kern, lldb_command, lldb_type_summary

import json
import kmemory

def pages_to_mib(pages):
    page_size = kern.globals.page_size
    return float(pages) * page_size / 1024 / 1024

def print_value_pages(name, value):
    print(f'{name + ":":<30s}\t{value} pages ({pages_to_mib(value):.3f} MiB)')

def print_value_bool(name, value):
    print(f'{name + ":":<30s}\t{"YES" if value else "NO"}')

def DescribeNanoTime(nanoseconds) -> str:
    us = nanoseconds / 1000

    td = timedelta(microseconds=us)
    return str(td) + f' ({nanoseconds:d} ns)'

class CompressorInfo():
    def __init__(self):
        self.compressor_pages = kern.globals.compressor_object.resident_page_count
        self.available_ncomp_pages = (kern.globals.vm_page_active_count +
                             kern.globals.vm_page_inactive_count +
                             kern.globals.vm_page_free_count +
                             kern.globals.vm_page_speculative_count)
        self.available_pages = self.compressor_pages + self.available_ncomp_pages

        self.minor_segment_count = kern.globals.c_minor_count
        self.major_segment_count = kern.globals.c_major_count
        self.filling_segment_count = kern.globals.c_filling_count
        self.aging_segment_count = kern.globals.c_age_count
        self.io_segment_count = kern.globals.c_swapio_count
        self.bad_segment_count = kern.globals.c_bad_count
        self.reg_swapout_segment_count = kern.globals.c_regular_swapout_count
        self.early_swapout_segment_count = kern.globals.c_early_swapout_count
        self.late_swapout_segment_count = kern.globals.c_late_swapout_count
        self.reg_swappedin_segment_count = kern.globals.c_regular_swappedin_count
        self.early_swappedin_segment_count = kern.globals.c_early_swappedin_count
        self.late_swappedin_segment_count = kern.globals.c_late_swappedin_count

        self.segment_count = kern.globals.c_segment_count
        self.swapped_segment_count = kern.globals.c_swappedout_count
        self.swapped_sparse_segment_count = kern.globals.c_swappedout_sparse_count

        self.majorcompact_threshold = self.available_pages * 10 // kern.globals.vm_compressor_majorcompact_threshold_divisor
        self.minorcompact_threshold = self.available_pages * 10 // kern.globals.vm_compressor_minorcompact_threshold_divisor

        self.segment_max_size = kern.globals.c_seg_max_pages

        self.segments_limit = kern.globals.c_segments_limit
        self.segments_hwm = kern.globals.c_segments_nearing_limit

        self.compressed_pages = kern.globals.c_segment_pages_compressed
        self.compressed_pages_hwm = kern.globals.c_segment_pages_compressed_nearing_limit
        self.compressed_pages_limit = kern.globals.c_segment_pages_compressed_limit

        self.now = kern.GetNanotimeFromAbstime(kern.globals.debugger_trap_timestamps[0])
        if self.now == 0:
            ## system hasn't panicked
            self.now = kern.GetNanotimeFromAbstime(GetRecentTimestamp())

        self.last_failed_swapfile_create = kern.GetNanotimeFromAbstime(kern.globals.vm_swapfile_last_failed_to_create_ts)
        self.swapfile_creation_backoff = kern.globals.vm_swapfile_creation_delay_ns
        self.last_successful_swapfile_create = kern.GetNanotimeFromAbstime(kern.globals.vm_swapfile_last_successful_create_ts)
        if hasattr(kern.globals, 'last_no_space_action_ts'):
                self.last_no_space_action = kern.GetNanotimeFromAbstime(kern.globals.last_no_space_action_ts)
                self.no_space_backoff = kern.globals.no_paging_space_action_throttle_delay_ns
        else:
                self.last_no_space_action = None
                self.no_space_backoff = None


    @property
    def incore_segment_count(self):
        return self.segment_count - self.swapped_segment_count - self.swapped_sparse_segment_count

    @property
    def incore_fragmentation_pct(self):
        if self.compressor_pages == 0:
            return 0
        else:
            return 1 - (self.compressor_pages / (self.incore_segment_count * self.segment_max_size))

    @property
    def incore_fragmentation_amount(self):
            return (self.incore_segment_count * self.segment_max_size) - self.compressor_pages

    @property
    def compression_ratio(self):
        if self.compressor_pages == 0:
            return 0
        else:
            return self.compressed_pages / (self.segment_count * self.segment_max_size)

    def is_fragmented(self):
        return self.incore_fragmentation_pct > (1 / 8)

    @property
    def swapped_fragmentation_pct(self):
        return self.swapped_bytes_unused / (self.swapped_bytes_unused + self.swapped_bytes_used)

    def ready_for_majorcompact(self):
        return self.available_ncomp_pages < self.majorcompact_threshold

    def ready_for_minorcompact(self):
        return self.available_ncomp_pages < self.minorcompact_threshold

    def anon_count_is_low(self):
        return kern.globals.vm_page_anonymous_count < kern.globals.vm_page_inactive_count // 20

    def external_queue_is_throttled(self):
        vm_pageout_queue_external = kern.globals.vm_pageout_queue_external
        return vm_pageout_queue_external.pgo_laundry >= vm_pageout_queue_external.pgo_maxlaundry

    def free_count_is_low(self):
        return (kern.globals.vm_page_free_count <
                (kern.globals.vm_page_free_reserved -
                 (kern.globals.vm_page_free_reserved_compressor_limit * 2)))

    def needs_to_swap(self):
        return (self.ready_for_majorcompact() or
                self.available_ncomp_below_min() or
                (self.external_queue_is_throttled() and self.anon_count_is_low()) or
                self.free_count_is_low() or
                (self.is_fragmented() and (self.segment_count >= self.segments_hwm // 8)))

# Macro: showcompressorinfo

def print_value_segments(name, value):
    print(f'{name + ":":<30s}\t{value} segs ({pages_to_mib(value * kern.globals.c_seg_max_pages):.3f} MiB)')

@lldb_command('showcompressorinfo')
def ShowCompressorInfo(cmd_args=None, cmd_options={}):
    '''
    Show high-level diagnostic information regarding the state of the compressor pool.
    '''
    compressor_info = CompressorInfo()

    print_value_pages('Compressor Resident Size', compressor_info.compressor_pages)
    print_value_pages('Available Non-Compressed Mem', compressor_info.available_ncomp_pages)
    print_value_pages('Available Mem', compressor_info.available_pages)

    print_value_pages('Minor Compaction Threshold', compressor_info.minorcompact_threshold)
    print_value_bool('Ready for Minor Compaction', compressor_info.ready_for_minorcompact())
    print_value_pages('Major Compaction Threshold', compressor_info.majorcompact_threshold)
    print_value_bool('Ready for Major Compaction', compressor_info.ready_for_majorcompact())

    print('')
    print_value_segments(f'Aging Segments', compressor_info.aging_segment_count)
    print_value_segments(f'Filling Segments', compressor_info.filling_segment_count)
    print_value_segments(f'Minor Segments', compressor_info.minor_segment_count)
    print_value_segments(f'Major Segments', compressor_info.major_segment_count)
    print_value_segments(f'Bad Segments', compressor_info.bad_segment_count)
    print_value_segments(f'SwapIO Segments', compressor_info.io_segment_count)
    print_value_segments(f'Swap-out (Early) Segments', compressor_info.early_swapout_segment_count)
    print_value_segments(f'Swap-out (Reg) Segments', compressor_info.reg_swapout_segment_count)
    print_value_segments(f'Swap-out (Late) Segments', compressor_info.late_swapout_segment_count)
    print_value_segments(f'Swapped-in (Early) Segments', compressor_info.early_swappedin_segment_count)
    print_value_segments(f'Swapped-in (Reg) Segments', compressor_info.reg_swappedin_segment_count)
    print_value_segments(f'Swapped-in (Late) Segments', compressor_info.late_swappedin_segment_count)
    print('-' * len('Swapped-in (Late) Segments'))
    print_value_segments('In-core Segments', compressor_info.incore_segment_count)
    print_value_segments('Swapped Segments', compressor_info.swapped_segment_count)
    print_value_segments('Swapped & Sparse Segments', compressor_info.swapped_sparse_segment_count)
    print('-' * len('Swapped & Sparse Segments'))
    print_value_segments('Total Segments', compressor_info.segment_count)

    print('')
    print_value_segments('Segments Nearing Limit', compressor_info.segments_hwm)
    print_value_segments('Segments Limit', compressor_info.segments_limit)
    print_value_pages('Max Segment Size', compressor_info.segment_max_size)

    print('')
    print_value_pages(f'In-Core Fragmentation Amount', compressor_info.incore_fragmentation_amount)
    print(f'In-Core Fragmentation Pct:\t{compressor_info.incore_fragmentation_pct:.1%}%')
    print_value_bool('Compressor Fragmented', compressor_info.is_fragmented())

    print('')
    print_value_pages('Compressed Pages', compressor_info.compressed_pages)
    print_value_pages('Compressed Pages Nearing Limit', compressor_info.compressed_pages_hwm)
    print_value_pages('Compressed Pages Limit', compressor_info.compressed_pages_limit)
    print(f'Compression Ratio: {compressor_info.compression_ratio:.3f}')

    print('')
    print(f'Now:                               {DescribeNanoTime(compressor_info.now)}')
    print(f'Last Failed Swapfile Creation:     {DescribeNanoTime(compressor_info.last_failed_swapfile_create)}')
    print(f'Last Successful Swapfile Creation: {DescribeNanoTime(compressor_info.last_successful_swapfile_create)}')
    if compressor_info.last_no_space_action is not None:
            print(f'Last No Paging Space Action:       {DescribeNanoTime(compressor_info.last_no_space_action)}')
            print(f'No Paging Space Backoff:           {DescribeNanoTime(compressor_info.no_space_backoff)}')
    print(f'Swapfile Creation Backoff:         {DescribeNanoTime(compressor_info.swapfile_creation_backoff)}')

# EndMacro: showcompressorinfo

# Macro: showswapperstats

@lldb_type_summary('compressor_swapper_stats')
def GetCompressorSwapperStats(cswap_stats):
    return (f'Unripe <30s:  {cswap_stats.unripe_under_30s}\n'
            f'Unripe <60s:  {cswap_stats.unripe_under_60s}\n'
            f'Unripe <300s: {cswap_stats.unripe_under_300s}\n'
            f'Swapins (reclaim): {cswap_stats.reclaim_swapins}\n'
            f'Swapins (defrag):  {cswap_stats.defrag_swapins}\n'
            f'Cswap Triggered: {cswap_stats.compressor_swap_threshold_exceeded}\n'
            f'Ext-q throttled: {cswap_stats.external_q_throttled}\n'
            f'Free<Reserved: {cswap_stats.free_count_below_reserve}\n'
            f'Thrashing: {cswap_stats.thrashing_detected}\n'
            f'Fragmented: {cswap_stats.fragmentation_detected}')

@lldb_command('showswapperstats')
def ShowSwapperStats(cmd_args=None, cmd_options={}):
    '''
    Show statistics relating to swap effectiveness
    '''
    print(GetCompressorSwapperStats(kern.globals.vmcs_stats))

# EndMacro: showswapperstats

# Macro: showallcompressorsegments

class SegmentState(Enum):
    EMPTY = 0
    FREE = 1
    FILLING = 2
    AGING = 3
    SWAPPINGOUT = 4
    SWAPPED = 5
    SWAPPED_SPARSE = 6
    SWAPPINGIN = 7
    MAJORCOMPACTED = 8
    BAD = 9
    SWAPIO = 10

class CompressorSegmentInfo:
    def __init__(self, segment):
        self.addr = int(segment)
        self.segno = int(segment.c_mysegno)
        self.state = SegmentState(int(segment.c_state)).name
        self.slots_used = segment.c_slots_used
        self.used_kb= segment.c_bytes_used / 1024
        self.unused_kb = segment.c_bytes_unused / 1024
        self.utilization_pct = segment.c_bytes_used / kern.globals.c_seg_bufsize * 100
        self.agedin_ts = segment.c_agedin_ts
        self.swappedin_ts = segment.c_swappedin_ts
        self.creation_ts = segment.c_creation_ts
        self.donated = 'Y' if segment.c_has_donated_pages == 1 else 'N'
        self.deferred_compact = 'Y' if segment.c_on_minorcompact_q == 1 else 'N'
        if hasattr(segment, 'c_has_freezer_pages'):
            self.frozen = 'Y' if segment.c_has_freezer_pages == 1 else 'N'
        else:
            self.frozen = 'N'

    def __str__(self):
        return (f'0x{self.addr:<16x} '
                f'{self.state:>16s} '
                f'{self.slots_used:>6d} '
                f'{self.used_kb:>10.3f} '
                f'{self.unused_kb:>11.3f} '
                f'{self.utilization_pct:>6.2f}% '
                f'{self.donated:>7s} '
                f'{self.frozen:>7s} '
                f'{self.deferred_compact:>5s} '
                f'{self.creation_ts:>16d} '
                f'{self.agedin_ts:>16d} '
                f'{self.swappedin_ts:>16d}')


@lldb_type_summary(['c_segment', 'c_segment_t'])
@header(f'{"ADDR":<18s} '
        f'{"STATE":>16s} '
        f'{"SLOTS":>6s} '
        f'{"USED(KiB)":>10s} '
        f'{"UNUSED(KiB)":>11s} '
        f'{"UTIL":>7s} '
        f'{"DONATED":>7s} '
        f'{"FREEZER":>7s} '
        f'{"DEFER":>5s} '
        f'{"CREATED_SEC":>16s} '
        f'{"AGED_IN_SEC":>16s} '
        f'{"SWAPPED_IN_SEC":>16s}')
def GetCompressorSegmentSummary(segment):
    info = CompressorSegmentInfo(segment)
    return str(info)

@lldb_command('showallcompressorsegments', 'H:')
def ShowAllCompressorSegments(cmd_args=None, cmd_options={}):
    '''
    Show all compressor segments

    usage: showallcompressorsegments [-H samples]

        -H n    Show only `n` segments
    '''
    totals = {
        'slots': 0,
        'used': 0,
        'unused': 0,
    }
    c_segments = kern.globals.c_segments
    print(GetCompressorSegmentSummary.header)

    num_segments = kern.globals.c_segments_available
    if '-H' in cmd_options:
        num_segments = min(num_segments, int(cmd_options['-H']))

    for i in range(num_segments):
        c_segments_elt = GetObjectAtIndexFromArray(c_segments, i)
        if c_segments_elt.c_segno < kern.globals.c_segments_limit or c_segments_elt.c_segno == 0xffffffff:
            ## segment is not allocated
            print(f'{NULL:<18s}{"FREE":>16s}')
        else:
            ## segment is allocated
            segment = c_segments_elt.c_seg
            print(GetCompressorSegmentSummary(segment))
            totals['used'] += segment.c_bytes_used / 1024
            totals['unused'] += segment.c_bytes_unused / 1024
            totals['slots'] += segment.c_slots_used

    print(f'{"TOTAL":<18s} {"-":>16s} '
          f'{totals["slots"]:>12d} {totals["used"]:>16.3f} '
          f'{totals["unused"]:>16.3f}')

# EndMacro: showallcompressorsegments

# Macro: showcompactorstats

class CompactorStats(Iterable):
    def __init__(self, num_samples: Optional[int] = None):
        self.num_samples = num_samples
        self.now = kern.globals.c_seg_major_compact_stats_now
        self.stats = kern.globals.c_seg_major_compact_stats
        self.num_stats = sizeof(self.stats) // sizeof(self.stats[0])

    def __iter__(self):
        self.samples_iterated = 0
        self.index = self.now - 1 if self.now > 0 else self.num_stats - 1
        return self

    ## Iterate stats in reverse chronological order
    def __next__(self):
        if self.index == self.now:
            raise StopIteration

        if (self.num_samples is not None and
            self.samples_iterated == self.num_samples):
            raise StopIteration

        self.samples_iterated += 1

        if self.index == 0:
            self.index = self.num_stats - 1
        else:
            self.index -= 1

        return self

    def __str__(self):
       stat = self.stats[self.index]
       return (f'{stat.asked_permission:12d} '
              f'{stat.compactions:12d} '
              f'{stat.moved_slots:12d} '
              f'{stat.moved_bytes:12d} '
              f'{stat.wasted_space_in_swapouts:15d} '
              f'{stat.count_of_swapouts:12d} '
              f'{stat.count_of_freed_segs:12d} '
              f'{stat.bailed_compactions:12d} '
              f'{stat.bytes_freed_rate_us:12d} ')

@header(f"{'CONSIDERED':>12s} "
        f"{'COMPACTIONS':>12s} "
        f"{'MOVED(SLT)':>12s} "
        f"{'MOVED(B)':>12s} "
        f"{'SWP_WASTED(B)':>15s} "
        f"{'SWAPOUTS':>12s} "
        f"{'FREED(SEGS)':>12s} "
        f"{'BAILED':>12s} "
        f"{'FREED(B/us)':>12s} ")
@lldb_command('showcompactorstats', 'H:')
def ShowCompactorStats(cmd_args=None, cmd_options={}):
    '''
    Dump a recent history of VM page dispostions in reverse chronological order.

    usage: showvmpagehistory [-N samples]

        -N n    Show only `n` most recent samples
    '''
    num_samples = cmd_options['-N'] if '-N' in cmd_options else None

    print(ShowCompactorStats.header)
    for stat in CompactorStats(num_samples):
        print(str(stat))

# EndMacro: showcompactorstats

# Macro: walkcsegqueue

@lldb_command('walkcsegqueue', 'N:')
def WalkCSegQueue(cmd_args=None, cmd_options={}):
    ''' Walk one or more compressor segment queues in age order.

    usage: walkcsegqueue <queue-name> [queue-name ...] [-N <n>]

        <queue-name>    One of: minor, age, major, early_swapout,
                        regular_swapout, late_swapout, swappedout,
                        swappedout_sparse, early_swappedin,
                        regular_swappedin, late_swappedin,
                        bad, swapio

        -N <n>          A limit on the number of segments to show per queue
        -R              Iterate the queue backwards

    '''

    if not cmd_args:
        raise ArgumentError('Must specify queue to walk')

    if '-N' in cmd_options:
        max_segments = int(cmd_options['-N'])
    else:
        max_segments = 0

    backwards = '-R' in cmd_options

    queue_heads = {
        'minor': kern.globals.c_minor_list_head,
        'age': kern.globals.c_age_list_head,
        'major': kern.globals.c_major_list_head,
        'early_swapout': kern.globals.c_early_swapout_list_head,
        'regular_swapout': kern.globals.c_regular_swapout_list_head,
        'late_swapout': kern.globals.c_late_swapout_list_head,
        'early_swappedin': kern.globals.c_early_swappedin_list_head,
        'regular_swappedin': kern.globals.c_regular_swappedin_list_head,
        'late_swappedin': kern.globals.c_late_swappedin_list_head,
        'swappedout': kern.globals.c_swappedout_list_head,
        'swappedout_sparse': kern.globals.c_swappedout_sparse_list_head,
        'swapio': kern.globals.c_swapio_list_head,
        'bad': kern.globals.c_bad_list_head,
    }

    for queue_name in cmd_args:
        queue_name = queue_name.lower()
        if queue_name not in queue_heads:
            raise ArgumentError(f'{queue_name} is not a valid queue name')

        head = queue_heads[queue_name]
        elt_name = 'c_list' if queue_name == 'minor' else 'c_age_list'
        i = 0

        print(GetCompressorSegmentSummary.header)
        for segment in IterateQueue(head, 'c_segment_t', elt_name, backwards=backwards):
            print(GetCompressorSegmentSummary(segment))
            if max_segments:
                i += 1
                if i >= max_segments:
                    break

        print('')

# EndMacro: walkcsegqueue

# Macro: showallcompressortimestamps

def GetPagerSlotNo(pager, slot_idx):
    if pager.cpgr_num_slots <= 2:
        slot = pager.cpgr_slots.cpgr_eslots[slot_idx]
    elif pager.cpgr_num_slots <= 128:
        if pager.cpgr_slots.cpgr_dslots != 0:
            slot = pager.cpgr_slots.cpgr_dslots[slot_idx]
        else:
            slot = 0
    else:
        chunk_idx = slot_idx // 128
        chunk_subidx = slot_idx % 128
        if (pager.cpgr_slots.cpgr_islots != 0 and
            pager.cpgr_slots.cpgr_islots[chunk_idx] != 0):
            slot = pager.cpgr_slots.cpgr_islots[chunk_idx][chunk_subidx]
        else:
            slot = 0
    return slot

def GetPagerSlotTimestamp(pager, slot_idx):
    if (not hasattr(kern.globals, 'vm_compressor_age_tracking') or
        kern.globals.vm_compressor_age_tracking == 0):
        return

    if pager.cpgr_num_slots <= 2:
        slot_ts = pager.cpgr_ts.cpgr_ets[slot_idx]
    elif pager.cpgr_num_slots <= 128:
        if pager.cpgr_ts.cpgr_dts != 0:
            slot_ts = pager.cpgr_ts[slot_idx]
        else:
            slot_ts = 0
    else:
        chunk_idx = slot_idx // 128
        chunk_subidx = slot_idx % 128
        if (pager.cpgr_ts.cpgr_its != 0 and
            pager.cpgr_ts.cpgr_its[chunk_idx] != 0):
            slot_ts = pager.cpgr_ts.cpgr_its[chunk_idx][chunk_subidx]
        else:
            slot_ts = 0
    return kern.GetNanotimeFromAbstime(slot_ts)

@header(f'{"PAGER":18s} {"VM_OBJECT":18s} {"OFFSET":18s} {"SLOT_ID":8s} {"NS":8s}')
@lldb_command('showallcompressorslots', 'J')
def ShowAllCompressorSlots(cmd_args=None, cmd_options={}):
    '''
    Show all compressor pager slots

    usage: showallcompressorslots [-J]

        -J      write output in json format
    '''

    as_json = '-J' in cmd_options

    if as_json:
        jdata = {}
    else:
        print(ShowAllCompressorSlots.header)

    pager_ty = gettype('struct compressor_pager')
    pagers = [
        pgr for pgr in kmemory.Zone("compressor_pager").iter_allocated(pager_ty)
    ]

    for pager in pagers:
        pager_id = int(AddressOf(pager))
        vm_object_id = int(pager.cpgr_hdr.mo_control)
        num_slots = int(pager.cpgr_num_slots)
        slots_occupied = int(pager.cpgr_num_slots_occupied)
        if not as_json:
            jdata[pager_id] = {
                'vm_object': '0x{:x}'.format(vm_object_id),
                'num_slots': num_slots,
                'slots_occupied': slots_occupied,
                'slots': []
            }
        for slot_idx in range(pager.cpgr_num_slots):
            ts = GetPagerSlotTimestamp(pager, slot_idx)
            slot_no = GetPagerSlotNo(pager, slot_idx)
            
            if slot_no != 0:
                offset = slot_idx * kern.globals.page_size
                if as_json:
                    jdata[pager_id]['slots'].append({
                        'offset': slot_idx,
                        'slot_id': int(slot_no),
                        'ts': int(ts),
                    })
                else:
                    print(f'0x{pager_id:<016x} 0x{vm_object_id:<016x} 0x{offset:16x} {int(slot_no):8d} {int(ts):8d}')

    if as_json:
        print(json.dumps(jdata, indent=4))

# EndMacro: showallcompressortimestamps
