from core.cvalue import sizeof, value
from enum import Enum
from memory import GetLedgerEntryWithName, Memstats
from process import GetProcName, GetProcPID, GetTaskFromProc, GetTaskSummary, ledger_limit_infinity
from scheduler import GetRecentTimestamp
from utils import Cast
from xnu import header, kern, lldb_command, unsigned
from xnudefines import JETSAM_PRIORITY_MAX, P_MEMSTAT_FROZEN


# Macro: showmemorystatus

class PControlAction(Enum):
    # See proc_internal.h
    NONE = 0
    THROTTLE = 1
    SUSPEND = 2
    KILL = 3

class RelaunchProbability(Enum):
    # See kern_memorystatus.h
    LOW = 1
    MED = 2
    HIGH = 4

def CalculateLedgerPeak(phys_footprint_entry):
    """
    Internal function to calculate ledger peak value for the given phys footprint entry
    params: phys_footprint_entry - value representing struct ledger_entry *
    return: value - representing the ledger peak for the given phys footprint entry
    """
    return max(phys_footprint_entry['balance'], phys_footprint_entry.get('interval_max', 0))

@header(f'{"cur_pri": <12s} '
        f'{"name": <32s} '
        f'{"pid": >8s} '
        f'{"req_pri": >12s} '
        f'{"ast_pri": >12s} '
        f'{"state": >12s} '
        f'{"dirty": >12s} '
        f'{"relaunch": >10s} '
        f'{"pcontrol": >10s} '
        f'{"paction": >10s} '
        f'{"footprint": >12s} '
        f'{"max_footprint": >13s} '
        f'{"limit": >12s}')
def GetMemoryStatusNode(proc):
    """
    Internal function to get memorystatus information from the given proc
    params: proc - value representing struct proc *
    return: str - formatted output information for proc object
    """

    task_val = GetTaskFromProc(proc)
    if task_val is None:
        return ''

    task_ledgerp = task_val.ledger
    ledger_template = kern.globals.task_ledger_template

    task_physmem_footprint_ledger_entry = GetLedgerEntryWithName(ledger_template, task_ledgerp, 'phys_mem')
    task_iokit_footprint_ledger_entry = GetLedgerEntryWithName(ledger_template, task_ledgerp, 'iokit_mapped')
    task_phys_footprint_ledger_entry = GetLedgerEntryWithName(ledger_template, task_ledgerp, 'phys_footprint')
    page_size = kern.globals.page_size

    phys_mem_footprint = task_physmem_footprint_ledger_entry['balance'] // 1024
    iokit_footprint = task_iokit_footprint_ledger_entry['balance'] // 1024
    phys_footprint = task_phys_footprint_ledger_entry['balance'] // 1024
    if task_phys_footprint_ledger_entry['limit'] == ledger_limit_infinity:
        phys_footprint_limit = '-'
    else:
        phys_footprint_limit = str(task_phys_footprint_ledger_entry['limit'] // 1024)
    ledger_peak = CalculateLedgerPeak(task_phys_footprint_ledger_entry) // 1024
    phys_footprint_spike = ledger_peak // 1024
    phys_footprint_lifetime_max = task_phys_footprint_ledger_entry['lifetime_max'] // 1024

    if proc.p_memstat_relaunch_flags != 0:
        relaunch_flags = RelaunchProbability(int(proc.p_memstat_relaunch_flags)).name
    else:
        relaunch_flags = '-'

    if proc.p_pcaction != 0:
        pc_control = PControlAction(proc.p_pcaction & 0xff).name
        pc_action = PControlAction((proc.p_pcaction & 0xff00) >> 16).name
    else:
        pc_control = '-'
        pc_action = '-'

    return (f'{proc.p_memstat_effectivepriority:<12d} '
            f'{GetProcName(proc):<32s} '
            f'{GetProcPID(proc):>8d} '
            f'{proc.p_memstat_requestedpriority:>12d} '
            f'{proc.p_memstat_assertionpriority:>12d} '
            f'{proc.p_memstat_state:#12x} '
            f'{proc.p_memstat_dirty:#12x} '
            f'{relaunch_flags:>10s} '
            f'{pc_control:>10s} '
            f'{pc_action:>10s} '
            f'{phys_footprint:>12d} '
            f'{phys_footprint_lifetime_max:>13d} '
            f'{phys_footprint_limit:>12s}')

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
