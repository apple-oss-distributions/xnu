"""
Macros relating to VM Pageout Scan.
"""
from core.cvalue import sizeof, value
import json
from memory import PrettyPrintDictionary
from process import GetTaskSummary
import re
from scheduler import GetRecentTimestamp
from typing import Iterable, Optional
from xnu import header, lldb_command, kern, xnudebug_test


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

@xnudebug_test('test_vmpageouthistory')
def TestMemstats(kernel_target, config, lldb_obj, isConnected ):
    """ Test the functionality of showvmpageouthistory command
        returns
         - False on failure
         - True on success
    """
    if not isConnected:
        print("Target is not connected. Cannot test memstats")
        return False
    res = lldb.SBCommandReturnObject()
    lldb_obj.debugger.GetCommandInterpreter().HandleCommand("showvmpageouthistory", res)
    result = res.GetOutput()
    if len(result.splitlines()) < 2:
        print("Result has fewer than two lines")
        return False
    for line in result.splitlines():
        matches = re.findall(r'(\d+|[\w_]+)', line)
        if len(matches) < 12:
            print("Line has fewer than 12 elements!")
            print(line)
            return False
    return True

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

@xnudebug_test('test_vmpageoutstats')
def TestMemstats(kernel_target, config, lldb_obj, isConnected ):
    """ Test the functionality of showvmpageoutstats command
        returns
         - False on failure
         - True on success
    """
    if not isConnected:
        print("Target is not connected. Cannot test showmvmpageoutstats")
        return False
    res = lldb.SBCommandReturnObject()
    lldb_obj.debugger.GetCommandInterpreter().HandleCommand("showvmpageoutstats", res)
    result = res.GetOutput()
    if len(result.splitlines()) < 2:
        print("Result has fewer than two lines")
        return False
    for line in result.splitlines():
        matches = re.findall(r'(\d|[\w_]+)', line)
        if len(matches) < 23:
            print("Line has fewer than 23 elements!")
            print(line)
            return False
    return True

# EndMacro: showvmpageoutstats

