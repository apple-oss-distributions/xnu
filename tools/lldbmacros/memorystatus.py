from core.cvalue import sizeof, value
from memory import GetLedgerEntryWithName, Memstats
from process import GetProcName, GetProcPID, GetTaskFromProc, GetTaskSummary
from scheduler import GetRecentTimestamp
from utils import Cast
from xnu import header, kern, lldb_command, unsigned
from xnudefines import JETSAM_PRIORITY_MAX, P_MEMSTAT_FROZEN


# Macro: showmemorystatus
def CalculateLedgerPeak(phys_footprint_entry):
    """
    Internal function to calculate ledger peak value for the given phys footprint entry
    params: phys_footprint_entry - value representing struct ledger_entry *
    return: value - representing the ledger peak for the given phys footprint entry
    """
    return max(phys_footprint_entry['balance'], phys_footprint_entry.get('interval_max', 0))

def IsProcFrozen(proc):
    if not proc:
        return 'N'
    return 'Y' if proc.p_memstat_state & P_MEMSTAT_FROZEN else 'N'

@header(f'{"effective": >12s} {"requested": >12s} {"assertion": >12s}'
        f'{"state": >12s} {"dirty": >12s}'
        f'{"frozen": >8s} {"relaunch": >10s} '
        f'{"physical": >14s} {"iokit": >10s} {"footprint": >12s} '
        f'{"recent_peak": >12s} {"lifemax": >10s} {"limit": >10s} '
        f'{"pid": >8s} {"name": <32s}\n'
        f'{"": >8s} {"priority": >12s} {"priority": >12s} '
        f'{"priority": >12s} {"": >12s} '
        f'{"": >8s} {"": >10s} '
        f'{"(pages)": >14s} {"(pages)": >10s} {"(pages)": >12s} '
        f'{"(pages)": >12s} {"(pages)": >10s} {"(pages)": >10s}  {"": <32s}')
def GetMemoryStatusNode(proc_val):
    """
    Internal function to get memorystatus information from the given proc
    params: proc - value representing struct proc *
    return: str - formatted output information for proc object
    """
    out_str = ''
    task_val = GetTaskFromProc(proc_val)
    if task_val is None:
        return out_str

    task_ledgerp = task_val.ledger
    ledger_template = kern.globals.task_ledger_template

    task_physmem_footprint_ledger_entry = GetLedgerEntryWithName(ledger_template, task_ledgerp, 'phys_mem')
    task_iokit_footprint_ledger_entry = GetLedgerEntryWithName(ledger_template, task_ledgerp, 'iokit_mapped')
    task_phys_footprint_ledger_entry = GetLedgerEntryWithName(ledger_template, task_ledgerp, 'phys_footprint')
    page_size = kern.globals.page_size

    phys_mem_footprint = task_physmem_footprint_ledger_entry['balance'] // page_size
    iokit_footprint = task_iokit_footprint_ledger_entry['balance'] // page_size
    phys_footprint = task_phys_footprint_ledger_entry['balance'] // page_size
    phys_footprint_limit = task_phys_footprint_ledger_entry['limit'] // page_size
    ledger_peak = CalculateLedgerPeak(task_phys_footprint_ledger_entry)
    phys_footprint_spike = ledger_peak // page_size
    phys_footprint_lifetime_max = task_phys_footprint_ledger_entry['lifetime_max'] // page_size

    format_string = '{:>12d} {:>12d} {:>12d} {:#012x} {:#012x} {:>8s} {:>10d} {:>14d} {:>10d} {:>12d}'
    out_str += format_string.format(
            proc_val.p_memstat_effectivepriority,
            proc_val.p_memstat_requestedpriority,
            proc_val.p_memstat_assertionpriority,
            proc_val.p_memstat_state,
            proc_val.p_memstat_dirty,
            IsProcFrozen(proc_val),
            proc_val.p_memstat_relaunch_flags,
            phys_mem_footprint,
            iokit_footprint,
            phys_footprint)
    if phys_footprint != phys_footprint_spike:
        out_str += ' {: >12d}'.format(phys_footprint_spike)
    else:
        out_str += ' {: >12s}'.format('-')
    out_str += ' {: >10d} {: >10d} {:>8d} {: <32s}'.format(
            phys_footprint_lifetime_max,
            phys_footprint_limit,
            GetProcPID(proc_val),
            GetProcName(proc_val))
    return out_str

@lldb_command('showmemorystatus')
def ShowMemoryStatus(cmd_args=None):
    """
    Routine to display each entry in jetsam list with a summary of pressure statistics
    Usage: showmemorystatus
    """
    bucket_index = 0
    print(GetMemoryStatusNode.header)
    while bucket_index <= JETSAM_PRIORITY_MAX:
        current_bucket = kern.globals.memstat_bucket[bucket_index]
        current_list = current_bucket.list
        current_proc = Cast(current_list.tqh_first, 'proc *')
        while unsigned(current_proc) != 0:
            print(GetMemoryStatusNode(current_proc))
            current_proc = current_proc.p_memstat_list.tqe_next
        bucket_index += 1

# EndMacro: showmemorystatus
