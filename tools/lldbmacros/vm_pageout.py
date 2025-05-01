"""
Macros relating to VM Pageout Scan.
"""
from core.cvalue import addressof, cast, sizeof, unsigned, value
import json
from memory import PrettyPrintDictionary
from collections import namedtuple
from process import GetTaskSummary
import re
from scheduler import GetRecentTimestamp
from typing import Iterable, Optional
from xnu import header, lldb_command, lldb_type_summary, kern, xnudebug_test


class VmPageoutStats(Iterable):
    def __init__(self, num_samples: Optional[int] = None):
        self.num_samples = num_samples
        self.stats = kern.globals.vm_pageout_stats
        self.num_stats = sizeof(self.stats) // sizeof(self.stats[0])
        self.now = kern.globals.vm_pageout_stat_now

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

    def page_counts(self) -> str:
       stat = self.stats[self.index]
       return (f'{stat.vm_page_active_count:12d} '
              f'{stat.vm_page_inactive_count:12d} '
              f'{stat.vm_page_speculative_count:12d} '
              f'{stat.vm_page_anonymous_count:12d} '
              f'{stat.vm_page_free_count:12d} '
              f'{stat.vm_page_wire_count:12d} '
              f'{stat.vm_page_compressor_count:12d} '
              f'{stat.vm_page_pages_compressed:12d} '
              f'{stat.vm_page_pageable_internal_count:12d} '
              f'{stat.vm_page_pageable_external_count:12d} '
              f'{stat.vm_page_realtime_count:12d} '
              f'{stat.vm_page_xpmapped_external_count:12d}')

    def page_stats(self) -> str:
        stat = self.stats[self.index]
        return (f'{stat.considered:12d} '
              f'{stat.pages_grabbed:12d} '
              f'{stat.pages_freed:12d} '
              f'{stat.pages_compressed:12d} '
              f'{stat.pages_evicted:12d} '
              f'{stat.pages_purged:12d} '
              f'{stat.skipped_external:12d} '
              f'{stat.skipped_internal:12d} '
              f'{stat.freed_speculative:12d} '
              f'{stat.freed_internal:12d} '
              f'{stat.freed_external:12d} '
              f'{stat.freed_cleaned:12d} '
              f'{stat.freed_internal:12d} '
              f'{stat.freed_external:12d} '
              f'{stat.inactive_referenced:12d} '
              f'{stat.inactive_nolock:12d} '
              f'{stat.reactivation_limit_exceeded:12d} '
              f'{stat.throttled_internal_q:12d} '
              f'{stat.throttled_external_q:12d} '
              f'{stat.forcereclaimed_sharedcache:12d} '
              f'{stat.forcereclaimed_realtime:12d} '
              f'{stat.protected_sharedcache:12d} '
              f'{stat.protected_realtime:12d}')

# Macro: showvmpagehistory

@header(f"{'active':>12s} "
        f"{'inactive':>12s} "
        f"{'speculative':>12s} "
        f"{'anonymous':>12s} "
        f"{'free':>12s} "
        f"{'wired':>12s} "
        f"{'compressor':>12s} "
        f"{'compressed':>12s} "
        f"{'pageable_int':>12s} "
        f"{'pageable_ext':>12s} "
        f"{'realtime':>12s} "
        f"{'xpmapped_ext':>12s}")
@lldb_command('showvmpageouthistory', 'S:')
def ShowVMPageoutHistory(cmd_args=None, cmd_options={}):
    '''
    Dump a recent history of VM page dispostions in reverse chronological order.

    usage: showvmpagehistory [-S samples]

        -S n    Show only `n` most recent samples (samples are collect at 1 Hz)
    '''
    num_samples = int(cmd_options['-S']) if '-S' in cmd_options else None

    print(ShowVMPageoutHistory.header)
    for stat in VmPageoutStats(num_samples):
        print(stat.page_counts())

# EndMacro: showvmpageouthistory

# Macro: showvmpageoutstats

@header(f"{'considered':>12s} "
        f"{'grabbed':>12s} "
        f"{'freed':>12s} "
        f"{'compressed':>12s} "
        f"{'evicted':>12s} "
        f"{'purged':>12s} "
        f"{'skipped_ext':>12s} "
        f"{'skipped_int':>12s} "
        f"{'freed_spec':>12s} "
        f"{'freed_int':>12s} "
        f"{'freed_ext':>12s} "
        f"{'cleaned':>12s} "
        f"{'cleaned_ext':>12s} "
        f"{'cleaned_int':>12s} "
        f"{'inact_ref':>12s} "
        f"{'inact_lck':>12s} "
        f"{'react_lim':>12s} "
        f"{'thrtl_int':>12s} "
        f"{'thrtl_ext':>12s} "
        f"{'forced_sc':>12s} "
        f"{'forced_rt':>12s} "
        f"{'prot_sc':>12s} "
        f"{'prot_rt':>12s}")
@lldb_command('showvmpageoutstats', 'S:')
def ShowVMPageoutStats(cmd_args=None, cmd_options={}):
    '''
    Dump a recent history of VM pageout statistics in reverse chronological order.

    usage: showvmpageoutstats [-S samples]

        -S n    Show only `n` most recent samples (samples are collect at 1 Hz)
    '''
    num_samples = int(cmd_options['-S']) if '-S' in cmd_options else None
    print(ShowVMPageoutStats.header)
    for stat in VmPageoutStats(num_samples):
        print(stat.page_stats())

# EndMacro: showvmpageoutstats

# Macro: showvmpageoutqueues

PageoutQueueSummary = namedtuple('VMPageoutQueueSummary', [
        'name', 'queue', 'laundry', 'max_laundry', 'busy', 'throttled',
        'low_pri', 'draining', 'initialized'])
PageoutQueueSummaryNames = PageoutQueueSummary(*PageoutQueueSummary._fields)
PageoutQueueSummaryFormat = ('{summary.queue:<18s} {summary.name:<12s} '
                             '{summary.laundry:>7s} {summary.max_laundry:>11s} '
                             '{summary.busy:>4s} {summary.throttled:>9s} '
                             '{summary.low_pri:>7s} {summary.draining:>8s} '
                             '{summary.initialized:>12s}')

@lldb_type_summary(['struct vm_pageout_queue'])
@header(PageoutQueueSummaryFormat.format(summary=PageoutQueueSummaryNames))
def GetVMPageoutQueueSummary(pageout_queue):
    ''' Dump a summary of the given pageout queue
    '''
    if addressof(pageout_queue) == kern.GetLoadAddressForSymbol('vm_pageout_queue_internal'):
        name = 'internal'
    elif addressof(pageout_queue) == kern.GetLoadAddressForSymbol('vm_pageout_queue_external'):
        name = 'external'
    elif ('vm_pageout_queue_benchmark' in kern.globals and
          addressof(pageout_queue) == kern.GetLoadAddressForSymbol('vm_pageout_queue_benchmark')):
        name = 'benchmark'
    else:
        name = 'unknown'
    summary = PageoutQueueSummary(name=name,
                                  queue=f'{addressof(pageout_queue.pgo_pending):<#018x}',
                                  laundry=str(unsigned(pageout_queue.pgo_laundry)),
                                  max_laundry=str(unsigned(pageout_queue.pgo_maxlaundry)),
                                  busy=("Y" if bool(pageout_queue.pgo_busy) else "N"),
                                  throttled=("Y" if bool(pageout_queue.pgo_throttled) else "N"),
                                  low_pri=("Y" if bool(pageout_queue.pgo_lowpriority) else "N"),
                                  draining=("Y" if bool(pageout_queue.pgo_draining) else "N"),
                                  initialized=("Y" if bool(pageout_queue.pgo_inited) else "N"))
    return PageoutQueueSummaryFormat.format(summary=summary)

@lldb_command('showvmpageoutqueues', '')
def ShowVMPageoutQueues(cmd_args=None, cmd_options={}):
    '''
    Print information about the various pageout queues.

    usage: showvmpageoutqueues
    '''

    internal_queue = kern.globals.vm_pageout_queue_internal
    external_queue = kern.globals.vm_pageout_queue_external
    print(GetVMPageoutQueueSummary.header)
    print(GetVMPageoutQueueSummary(internal_queue))
    print(GetVMPageoutQueueSummary(external_queue))
    try:
        benchmark_queue = kern.globals.vm_pageout_queue_benchmark
        print(GetVMPageoutQueueSummary(benchmark_queue))
    except:
        pass

# EndMacro: showvmpageoutqueues
