
""" Please make sure you read the README file COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file.
"""
from typing import Union, Optional
from xnu import *
import sys, shlex
from utils import *
from core.lazytarget import *
import time
import xnudefines
import kmemory
import memory
import json

from collections import defaultdict, namedtuple

NO_PROC_NAME = "unknown"
P_LHASTASK = 0x00000002
TF_HASPROC = 0x00800000

THREAD_STATE_CHARS = {
    0x0: '',
    0x1: 'W',
    0x2: 'S',
    0x4: 'R',
    0x8: 'U',
    0x10: 'H',
    0x20: 'A',
    0x40: 'P',
    0x80: 'I',
    0x100: 'K'
}
LAST_THREAD_STATE = 0x100

def GetProcPID(proc):
    """ returns the PID of a process.
        params:
            proc: value object representing a proc in the kernel.
        returns:
            int: the pid of the process.
    """
    return unsigned(proc.p_pid) if proc is not None else -1

def GetProcPlatform(proc):
    """ returns the platform identifier of a process.
        params:
            proc: value object representing a proc in the kernel.
        returns:
            int: the platform identifier of the process.
    """
    if not proc:
        return None
    return int(proc.p_proc_ro.p_platform_data.p_platform)

def GetProcName(proc):
    """ returns a string name of the process. Longer variant is preffered if provided.
        params:
            proc: value object representing a proc in the kernel.
        returns:
            str: a string name of the process linked to the task.
    """
    if proc is None:
        return NO_PROC_NAME
    name = str(proc.p_name)
    return name if name != '' else str(proc.p_comm)

def GetProcNameForTask(task):
    """ returns a string name of the process. If proc is not valid the proc
        name is looked up in the associated importance structure (if
        available). If no name can be found, "unknown"  is returned.
        params:
            task: value object represeting a task in the kernel.
        returns:
            str : A string name of the process linked to the task
    """
    if task:
        p = GetProcFromTask(task)
        if p is not None:
            return GetProcName(p)

        if ((task_imp_base := get_field(task, 'task_imp_base')) is not None and
           (iit_procname := get_field(task_imp_base, 'iit_procname')) is not None and
           unsigned(task_imp_base) != 0):
            return str(iit_procname)

    return NO_PROC_NAME

def GetProcPIDForTask(task):
    """ returns a int pid of the process. if the proc is not valid, val[5] from audit_token is returned.
        params:
            task: value object representing a task in the kernel
        returns:
            int : pid of the process or -1 if not found
    """
    if not task:
        return -1

    p = GetProcFromTask(task)
    if p is not None:
        return GetProcPID(p)

    proc_ro = Cast(task.bsd_info_ro, 'proc_ro *')
    pid = unsigned(proc_ro.task_tokens.audit_token.val[5])
    return pid

def GetProcStartAbsTimeForTask(task):
    if task:
        p = GetProcFromTask(task)
        if p is not None:
            return p.p_stats.ps_start
    return None

def GetProcInfo(proc):
    """ returns a string name, pid, parent and task for a proc_t. Decodes cred, flag and p_stat fields.
        params:
            proc : value object representing a proc in the kernel
        returns:
            str : A string describing various information for process.
    """
    out_string = ""
    out_string += ("Process {p: <#020x}\n\tname {0: <32s}\n\tpid:{1: <6d} " +
                   "task:{task: <#020x} p_stat:{p.p_stat: <6d} parent pid: {p.p_ppid: <6d}\n"
                   ).format(GetProcName(proc), GetProcPID(proc), task=GetTaskFromProc(proc), p=proc)
    #print the Creds
    ucred = proc.p_proc_ro.p_ucred.__smr_ptr
    if ucred:
        out_string += "Cred: euid {:d} ruid {:d} svuid {:d}\n".format(ucred.cr_posix.cr_uid,
                                                                      ucred.cr_posix.cr_ruid,
                                                                      ucred.cr_posix.cr_svuid )
    #print the flags
    flags = int(proc.p_flag)
    out_string += "Flags: {0: <#020x}\n".format(flags)
    num = 1
    while num <= flags:
        if flags & num:
            explain_str = xnudefines.proc_flag_explain_strings.get(num, 'unknown')
            out_string += "\t0x{:08x} - ".format(num) + explain_str + "\n"
        elif num == 0x4: #special case for 32bit flag
            out_string += "\t!0x00000004 - process is 32 bit\n"
        num = num << 1
    out_string += "State: "
    state_val = proc.p_stat
    if state_val < 1 or state_val > len(xnudefines.proc_state_strings) :
        out_string += "(Unknown)"
    else:
        out_string += xnudefines.proc_state_strings[int(state_val)]
    
    return out_string
    
def GetProcNameForPid(pid):
    """ Finds the name of the process corresponding to a given pid
        params:
            pid     : int, pid you want to find the procname for
        returns
            str     : Name of the process corresponding to the pid, "Unknown" if not found
    """
    for p in kern.procs:
        if int(GetProcPID(p)) == int(pid):
            return GetProcName(p)
    return NO_PROC_NAME

def GetProcForPid(search_pid):
    """ Finds the value object representing a proc in the kernel based on its pid
        params:
            search_pid  : int, pid whose proc structure you want to find
        returns:
            value       : The value object representing the proc, if a proc corresponding
                          to the given pid is found. Returns None otherwise
    """
    if search_pid == 0:
        return kern.globals.initproc
    else:
        headp = kern.globals.allproc
        for proc in IterateListEntry(headp, 'p_list'):
            if GetProcPID(proc) == search_pid:
                return proc
        return None

@lldb_command('allproc')
def AllProc(cmd_args=None):
    """ Walk through the allproc structure and print procinfo for each process structure. 
        params: 
            cmd_args - [] : array of strings passed from lldb command prompt
    """
    for proc in kern.procs :
        print(GetProcInfo(proc))
    

@lldb_command('zombproc')
def ZombProc(cmd_args=None):
    """ Routine to print out all procs in the zombie list
        params: 
            cmd_args - [] : array of strings passed from lldb command prompt
    """
    if any(kern.zombprocs):
        print("\nZombie Processes:")
        for proc in kern.zombprocs:
            print(GetProcInfo(proc) + "\n\n")

@lldb_command('zombtasks')
def ZombTasks(cmd_args=None):
    """ Routine to print out all tasks in the zombie list
        params: None
    """
    out_str = ""
    if any(kern.zombprocs):
        header = "\nZombie Tasks:\n"
        header += GetTaskSummary.header + " " + GetProcSummary.header
        for proc in kern.zombprocs:
            if proc.p_stat != 5:
                t = GetTaskFromProc(proc)
                out_str += GetTaskSummary(t) +" "+ GetProcSummary(proc) + "\n"
        if out_str != "":
            print(header)
            print(out_str)

# Macro: zombstacks
def ShowZombStacks(O=None, regex=None):
    header_flag = 0
    for proc in kern.zombprocs:
        if proc.p_stat != 5:
            if header_flag == 0:
                print("\nZombie Stacks:")
                header_flag = 1
            t = GetTaskFromProc(proc)
            if t is not None:
                ShowTaskStacks(t, O=O, regex=regex)

@lldb_command('zombstacks', fancy=True)
def ZombStacksCommand(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print out all stacks of tasks that are exiting
    """
    ShowZombStacks(O=O)
# EndMacro: zombstacks


""" AST Flags:
    P - AST_PREEMPT
    Q - AST_QUANTUM
    U - AST_URGENT
    H - AST_HANDOFF
    Y - AST_YIELD
    A - AST_APC
    L - AST_LEDGER
    B - AST_BSD
    K - AST_KPERF
    M - AST_MACF
    r - AST_RESET_PCS
    a - AST_ARCADE
    X - AST_MACH_EXCEPTION
    T - AST_TELEMETRY_USER
    T - AST_TELEMETRY_KERNEL
    T - AST_TELEMETRY_WINDOWED
    S - AST_SFI
    D - AST_DTRACE
    I - AST_TELEMETRY_IO
    E - AST_KEVENT
    R - AST_REBALANCE
    p - AST_PROC_RESOURCE
    d - AST_DEBUG_ASSERT
    T - AST_TELEMETRY_MACF
"""
_AST_CHARS = {
    0x1: 'P', 0x2: 'Q', 0x4: 'U', 0x8: 'H', 0x10: 'Y', 0x20: 'A',
    0x40: 'L', 0x80: 'B', 0x100: 'K', 0x200: 'M', 0x400: 'r', 0x800: 'a',
    0x1000: 'X', 0x2000: 'T', 0x4000: 'T', 0x8000: 'T', 0x10000: 'S',
    0x20000: 'D', 0x40000: 'I', 0x80000: 'E', 0x100000: 'R',
    0x400000: 'p', 0x800000: 'd', 0x1000000: 'T'
}


def GetASTSummary(ast):
    """ Summarizes an AST field """

    state = int(ast)
    state_str = ''

    for ast, char in _AST_CHARS.items():
        state_str += char if state & ast else ''

    return state_str


@lldb_type_summary(['kcdata_descriptor *', 'kcdata_descriptor_t'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: <10s} {4: <5s}".format("kcdata_descriptor", "begin_addr", "cur_pos", "size", "flags"))
def GetKCDataSummary(kcdata):
    """ Summarizes kcdata_descriptor structure
        params: kcdata: value - value object representing kcdata_descriptor
        returns: str - summary of the kcdata object
    """
    format_string = "{0: <#020x} {1: <#020x} {2: <#020x} {3: <10d} {4: <#05x}"
    return format_string.format(kcdata, kcdata.kcd_addr_begin, kcdata.kcd_addr_end, kcdata.kcd_length, kcdata.kcd_flags)

INVALID_TASK_SUMMARY = "Process is not valid."

@lldb_type_summary(['task', 'task_t'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: >5s} {4: <5s}".format("task","vm_map", "ipc_space", "#acts", "flags"))
def GetTaskSummary(task: Optional[value], showcorpse=False) -> str:
    """ Summarizes the important fields in task structure.
        params: task: value - value object representing a task in kernel
        returns: str - summary of the task
    """
    if task is None:
        return INVALID_TASK_SUMMARY

    out_string = ""
    format_string = '{0: <#020x} {1: <#020x} {2: <#020x} {3: >5d} {4: <5s}'
    thread_count = int(task.thread_count)
    task_flags = ''
    if hasattr(task, "suppression_generation") and (int(task.suppression_generation) & 0x1) == 0x1:
        task_flags += 'P'
    if hasattr(task, "effective_policy") and int(task.effective_policy.tep_sup_active) == 1:
        task_flags += 'N'
    if hasattr(task, "suspend_count") and int(task.suspend_count) > 0:
        task_flags += 'S'
    if hasattr(task, 'task_imp_base') and unsigned(task.task_imp_base):
        tib = task.task_imp_base
        if int(tib.iit_receiver) == 1:
            task_flags += 'R'
        if int(tib.iit_donor) == 1:
            task_flags += 'D'
        if int(tib.iit_assertcnt) > 0:
            task_flags += 'B'

    proc_ro = Cast(task.bsd_info_ro, 'proc_ro *')
    if unsigned(proc_ro) != 0:
        # check if corpse flag is set
        if unsigned(proc_ro.t_flags_ro) & 0x20:
            task_flags += 'C'

    if unsigned(task.t_flags) & 0x40:
        task_flags += 'P'

    out_string += format_string.format(task, task.map, task.itk_space, thread_count, task_flags)
    if showcorpse is True and unsigned(task.corpse_info) != 0:
        out_string += " " + GetKCDataSummary(task.corpse_info)
    return out_string

@header("{0: <28s}".format("task_role"))
def GetTaskRoleSummary(task):
    """ Summarizes task_role structure
        params: task: value - value object representing task
        returns: str - summary of the task role string
    """
    format_string = "{0: <28s}"
    task_role = task.effective_policy.tep_role
    return format_string.format(GetTaskRoleString(task_role))

def GetMachThread(uthread):
    """ Converts the passed in value interpreted as a uthread_t into a thread_t
    """
    addr = unsigned(uthread) - sizeof('struct thread')
    thread = kern.GetValueFromAddress(addr, 'struct thread *')
    return thread

def GetBSDThread(thread: Union[lldb.SBValue, value]) -> value:
    """ Converts the passed in value interpreted as a thread_t into a uthread_t
    """
    addr = unsigned(thread) + sizeof('struct thread')
    return kern.CreateValueFromAddress(addr, 'struct uthread')

def GetProcFromTask(task) -> Optional[value]:
    """ Converts the passed in value interpreted as a task_t into a proc_t
    """
    task_addr = unsigned(task)
    if task_addr and unsigned(task.t_flags) & TF_HASPROC:
        addr = task_addr - kern.globals.proc_struct_size
        return value(task.GetSBValue().xCreateValueFromAddress(
            'proc', addr, gettype('struct proc')
        ).AddressOf())
    return None

def GetTaskFromProc(proc) -> Optional[value]:
    """ Converts the passed in value interpreted as a proc_t into a task_t
    """
    proc_addr = unsigned(proc)
    if proc_addr and unsigned(proc.p_lflag) & P_LHASTASK:
        addr = proc_addr + kern.globals.proc_struct_size
        return value(proc.GetSBValue().xCreateValueFromAddress(
            'task', addr, gettype('struct task')
        ).AddressOf())
    return None

def GetThreadNameFromBSDThread(uthread):
    """ Get the name of a thread from a BSD thread, if possible.
        Returns the empty string otherwise.
    """
    if int(uthread.pth_name) != 0 :
        th_name_strval = Cast(uthread.pth_name, 'char *')
        if len(str(th_name_strval)) > 0 :
            return str(th_name_strval)

    return ''

def GetThreadName(thread):
    """ Get the name of a thread, if possible.  Returns the empty string
        otherwise.
    """
    uthread = GetBSDThread(thread)
    return GetThreadNameFromBSDThread(uthread)

ThreadSummary = namedtuple('ThreadSummary', [
        'thread', 'tid', 'task', 'processor', 'base', 'pri', 'sched_mode', 'io_policy',
        'state', 'ast', 'waitq', 'wait_evt', 'wait_evt_sym', 'wait_msg',
        'name'])
ThreadSummaryNames = ThreadSummary(*ThreadSummary._fields)
ThreadSummaryFormat = (
        '{ts.thread: <20s} {ts.tid: <10s} {ts.task: <20s} {ts.processor: <20s} {ts.base: <6s} '
        '{ts.pri: <6s} {ts.sched_mode: <10s} {ts.io_policy: <15s} '
        '{ts.state: <8s} {ts.ast: <12s} {ts.waitq: <18s} {ts.wait_evt: <18s} '
        '{ts.wait_evt_sym: <30s} {ts.wait_msg: <20s} {ts.name: <20s}')

@lldb_type_summary(['thread *', 'thread_t'])
@header(ThreadSummaryFormat.format(ts=ThreadSummaryNames))
def GetThreadSummary(thread, O=None):
    """ Summarize the thread structure.

        params: thread: value - value object representing a thread in kernel
        returns: str - summary of a thread
        
        State flags:
        W - Wait asserted
        S - Suspended
        R - Runnable
        U - Uninterruptible
        H - Terminated
        A - Terminated (on queue)
        I - Idle thread
        C - Crashed thread
        K - Waking

        policy flags:
        B - darwinbg
        T - IO throttle
        P - IO passive
        D - Terminated
    """

    # Check that this is a valid thread (if possible).
    if hasattr(thread, "thread_magic") and thread.thread_magic != 0x1234ABCDDCBA4321:
        # Do not raise exception so iterators like showscheduler don't abort.
        return f"{thread:<#018x} <invalid thread>"

    thread_ptr_str = '{:<#018x}'.format(thread)
    thread_task_ptr_str = '{:<#018x}'.format(thread.t_tro.tro_task)

    if int(thread.static_param):
        thread_ptr_str += ' W'
    thread_id = hex(thread.thread_id)
    processor = hex(thread.last_processor)
    base_priority = str(int(thread.base_pri))
    sched_priority = str(int(thread.sched_pri))
    sched_mode = ''
    mode = str(thread.sched_mode)
    if 'TIMESHARE' in mode:
        sched_mode += 'TMSHR'
    elif 'FIXED' in mode:
        sched_mode += 'FIXED'
    elif 'REALTIME' in mode:
        sched_mode += 'RT'
        
    if (unsigned(thread.bound_processor) != 0):
        sched_mode += ' BIND'
        
    TH_SFLAG_THROTTLED = 0x4
    if (unsigned(thread.sched_flags) & TH_SFLAG_THROTTLED):
        sched_mode += ' BG'
    
    uthread = GetBSDThread(thread)
    thread_name = GetThreadNameFromBSDThread(uthread)

    io_policy_str = ""
    if int(uthread.uu_flag) & 0x400:
        io_policy_str += 'RAGE '
    if int(thread.effective_policy.thep_darwinbg) != 0:
        io_policy_str += 'B'
    if int(thread.effective_policy.thep_io_tier) != 0:
        io_policy_str += 'T'
    if int(thread.effective_policy.thep_io_passive) != 0:
        io_policy_str += 'P'
    if int(thread.effective_policy.thep_terminated) != 0:
        io_policy_str += 'D'

    state = int(thread.state)
    state_str = ''
    mask = 0x1
    while mask <= LAST_THREAD_STATE:
        state_str += THREAD_STATE_CHARS[int(state & mask)]
        mask <<= 1
    
    if int(thread.inspection):
        state_str += 'C'

    ast = int(thread.ast) | int(thread.reason)
    ast_str = GetASTSummary(ast)
    
    wait_queue_str = ''
    wait_event_str = ''
    wait_event_str_sym = ''
    wait_message = ''
    if (state & 0x1) != 0:
        wait_queue_str = '{:<#018x}'.format(unsigned(thread.waitq.wq_q))
        wait_event_str = '{:<#018x}'.format(unsigned(thread.wait_event))
        wait_event_str_sym = kern.Symbolicate(int(hex(thread.wait_event), 16))
        if int(uthread.uu_wmesg) != 0:
            wait_message = str(Cast(uthread.uu_wmesg, 'char *'))

    ts = ThreadSummary(
            thread=thread_ptr_str, tid=thread_id,
            task=thread_task_ptr_str, processor=processor,
            base=base_priority, pri=sched_priority, sched_mode=sched_mode,
            io_policy=io_policy_str, state=state_str, ast=ast_str,
            waitq=wait_queue_str, wait_evt=wait_event_str,
            wait_evt_sym=wait_event_str_sym, wait_msg=wait_message,
            name=thread_name)
    if O is not None:
        return O.format(ThreadSummaryFormat, ts=ts)
    else:
        return ThreadSummaryFormat.format(ts=ts)


def GetTaskRoleString(role):
    role_strs = {
                -1 : "TASK_RENICED",
                 0 : "TASK_UNSPECIFIED",
                 1 : "TASK_FOREGROUND_APPLICATION",
                 2 : "TASK_BACKGROUND_APPLICATION",
                 3 : "TASK_CONTROL_APPLICATION",
                 4 : "TASK_GRAPHICS_SERVER",
                 5 : "TASK_THROTTLE_APPLICATION",
                 6 : "TASK_NONUI_APPLICATION",
                 7 : "TASK_DEFAULT_APPLICATION",
                 8 : "TASK_DARWINBG_APPLICATION"
                }
    return role_strs[int(role)]

def GetCoalitionFlagString(coal):
    flags = []
    if (coal.privileged):
        flags.append('privileged')
    if (coal.termrequested):
        flags.append('termrequested')
    if (coal.terminated):
        flags.append('terminated')
    if (coal.reaped):
        flags.append('reaped')
    if (coal.notified):
        flags.append('notified')
    if (coal.efficient):
        flags.append('efficient')
    return "|".join(flags)

def GetCoalitionTasks(queue, coal_type, thread_details=False):
    sfi_strs = {
                 0x0  : "SFI_CLASS_UNSPECIFIED",
                 0x1  : "SFI_CLASS_DARWIN_BG",
                 0x2  : "SFI_CLASS_APP_NAP",
                 0x3  : "SFI_CLASS_MANAGED_FOCAL",
                 0x4  : "SFI_CLASS_MANAGED_NONFOCAL",
                 0x5  : "SFI_CLASS_DEFAULT_FOCAL",
                 0x6  : "SFI_CLASS_DEFAULT_NONFOCAL",
                 0x7  : "SFI_CLASS_KERNEL",
                 0x8  : "SFI_CLASS_OPTED_OUT",
                 0x9  : "SFI_CLASS_UTILITY",
                 0xA  : "SFI_CLASS_LEGACY_FOCAL",
                 0xB  : "SFI_CLASS_LEGACY_NONFOCAL",
                 0xC  : "SFI_CLASS_USER_INITIATED_FOCAL",
                 0xD  : "SFI_CLASS_USER_INITIATED_NONFOCAL",
                 0xE  : "SFI_CLASS_USER_INTERACTIVE_FOCAL",
                 0xF  : "SFI_CLASS_USER_INTERACTIVE_NONFOCAL",
                 0x10 : "SFI_CLASS_MAINTENANCE",
                }
    tasks = []
    field_path = '.task_coalition[{}]'.format(coal_type)
    for task in IterateLinkageChain(queue, 'task *', field_path):
        task_str = "({0: <d},{1: #x}, {2: <s}, {3: <s})".format(GetProcPIDForTask(task),task,GetProcNameForTask(task),GetTaskRoleString(task.effective_policy.tep_role))
        if thread_details:
            for thread in IterateQueue(task.threads, "thread_t", "task_threads"):
                task_str += "\n\t\t\t|-> thread:" + hex(thread) + ", " + sfi_strs[int(thread.sfi_class)]
        tasks.append(task_str)
    return tasks

def GetCoalitionTypeString(type):
    """ Convert a coalition type field into a string
    Currently supported types (from <mach/coalition.h>):
        COALITION_TYPE_RESOURCE
        COALITION_TYPE_JETSAM
    """
    if type == 0: # COALITION_TYPE_RESOURCE
        return 'RESOURCE'
    if type == 1:
        return 'JETSAM'
    return '<unknown>'

def GetResourceCoalitionSummary(coal, verbose=False):
    """ Summarize a resource coalition
    """
    out_string = "Resource Coalition:\n\t  Ledger:\n"
    thread_details = False
    if config['verbosity'] > vSCRIPT:
        thread_details = True
    ledgerp = coal.r.ledger
    if verbose and unsigned(ledgerp) != 0:
        i = 0
        while i != ledgerp.l_template.lt_cnt:
            out_string += "\t\t"
            out_string += GetLedgerEntrySummary(kern.globals.task_ledger_template, ledgerp, i)
            i = i + 1
    out_string += "\t  bytesread {0: <d}\n\t  byteswritten {1: <d}\n\t  gpu_time {2: <d}".format(coal.r.bytesread, coal.r.byteswritten, coal.r.gpu_time)
    out_string += "\n\t  total_tasks {0: <d}\n\t  dead_tasks {1: <d}\n\t  active_tasks {2: <d}".format(coal.r.task_count, coal.r.dead_task_count, coal.r.task_count - coal.r.dead_task_count)
    out_string += "\n\t  last_became_nonempty_time {0: <d}\n\t  time_nonempty {1: <d}".format(coal.r.last_became_nonempty_time, coal.r.time_nonempty)
    if verbose:
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_DEFAULT] {0: <d}".format(coal.r.cpu_time_eqos[0])
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_MAINTENANCE] {0: <d}".format(coal.r.cpu_time_eqos[1])
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_BACKGROUND] {0: <d}".format(coal.r.cpu_time_eqos[2])
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_UTILITY] {0: <d}".format(coal.r.cpu_time_eqos[3])
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_LEGACY] {0: <d}".format(coal.r.cpu_time_eqos[4])
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_USER_INITIATED] {0: <d}".format(coal.r.cpu_time_eqos[5])
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_USER_INTERACTIVE] {0: <d}".format(coal.r.cpu_time_eqos[6])
    out_string += "\n\t  Tasks:\n\t\t"
    tasks = GetCoalitionTasks(addressof(coal.r.tasks), 0, thread_details)
    out_string += "\n\t\t".join(tasks)
    return out_string

def GetJetsamCoalitionSummary(coal, verbose=False):
    out_string = "Jetsam Coalition:"
    thread_details = False
    if config['verbosity'] > vSCRIPT:
        thread_details = True
    if unsigned(coal.j.leader) == 0:
        out_string += "\n\t  NO Leader!"
    else:
        out_string += "\n\t  Leader:\n\t\t"
        out_string += "({0: <d},{1: #x}, {2: <s}, {3: <s})".format(GetProcPIDForTask(coal.j.leader),coal.j.leader,GetProcNameForTask(coal.j.leader),GetTaskRoleString(coal.j.leader.effective_policy.tep_role))
    out_string += "\n\t  Extensions:\n\t\t"
    tasks = GetCoalitionTasks(addressof(coal.j.extensions), 1, thread_details)
    out_string += "\n\t\t".join(tasks)
    out_string += "\n\t  XPC Services:\n\t\t"
    tasks = GetCoalitionTasks(addressof(coal.j.services), 1, thread_details)
    out_string += "\n\t\t".join(tasks)
    out_string += "\n\t  Other Tasks:\n\t\t"
    tasks = GetCoalitionTasks(addressof(coal.j.other), 1, thread_details)
    out_string += "\n\t\t".join(tasks)
    out_string += "\n\t  Thread Group: {0: <#020x}\n".format(coal.j.thread_group)
    return out_string

@lldb_type_summary(['coalition_t', 'coalition *'])
@header("{0: <20s} {1: <15s} {2: <10s} {3: <10s} {4: <10s} {5: <12s} {6: <12s} {7: <20s}".format("coalition", "type", "id", "ref count", "act count", "focal cnt", "nonfocal cnt","flags"))
def GetCoalitionSummary(coal):
    if unsigned(coal) == 0:
        return '{0: <#020x} {1: <15s} {2: <10d} {3: <10d} {4: <10d} {5: <12d} {6: <12d} {7: <s}'.format(0, "", -1, -1, -1, -1, -1, "")
    out_string = ""
    format_string = '{0: <#020x} {1: <15s} {2: <10d} {3: <10d} {4: <10d} {5: <12d} {6: <12d} {7: <s}'
    type_string = GetCoalitionTypeString(coal.type)
    flag_string = GetCoalitionFlagString(coal)
    out_string += format_string.format(coal, type_string, coal.id, coal.ref_count, coal.active_count, coal.focal_task_count, coal.nonfocal_task_count, flag_string)
    return out_string

def GetCoalitionInfo(coal, verbose=False):
    """ returns a string describing a coalition, including details about the particular coalition type.
        params:
            coal : value object representing a coalition in the kernel
        returns:
            str : A string describing the coalition.
    """
    if unsigned(coal) == 0:
        return "<null coalition>"
    typestr = GetCoalitionTypeString(coal.type)
    flagstr = GetCoalitionFlagString(coal)
    out_string = ""
    out_string += "Coalition {c: <#020x}\n\tID {c.id: <d}\n\tType {c.type: <d} ({t: <s})\n\tRefCount {c.ref_count: <d}\n\tActiveCount {c.active_count: <d}\n\tFocal Tasks: {c.focal_task_count: <d}\n\tNon-Focal Tasks: {c.nonfocal_task_count: <d}\n\tFlags {f: <s}\n\t".format(c=coal,t=typestr,f=flagstr)
    if coal.type == 0: # COALITION_TYPE_RESOURCE
        out_string += GetResourceCoalitionSummary(coal, verbose)
    elif coal.type == 1: # COALITION_TYPE_JETSAM
        out_string += GetJetsamCoalitionSummary(coal, verbose)
    else:
        out_string += "Unknown Type"

    return out_string

# Macro: showcoalitioninfo

@lldb_command('showcoalitioninfo')
def ShowCoalitionInfo(cmd_args=None, cmd_options={}):
    """  Display more detailed information about a coalition
         Usage: showcoalitioninfo <address of coalition>
    """
    verbose = False
    if config['verbosity'] > vHUMAN:
        verbose = True
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")
    coal = kern.GetValueFromAddress(cmd_args[0], 'coalition *')
    if not coal:
        print("unknown arguments:", str(cmd_args))
        return False
    print(GetCoalitionInfo(coal, verbose))

# EndMacro: showcoalitioninfo

# Macro: showallcoalitions

@lldb_command('showallcoalitions')
def ShowAllCoalitions(cmd_args=None):
    """  Print a summary listing of all the coalitions
    """
    global kern
    print(GetCoalitionSummary.header)
    for c in kern.coalitions:
        print(GetCoalitionSummary(c))

# EndMacro: showallcoalitions

# Macro: showcurrentforegroundapps

@lldb_command('showcurrentforegroundapps')
def ShowCurrentForegroundStatus(cmd_args=None):
    """  Print current listing of foreground applications
    """
    global kern
    print(GetTaskSummary.header + " " + GetProcSummary.header + " " + GetTaskRoleSummary.header)
    for t in kern.tasks:
        task_role = t.effective_policy.tep_role
        # Only print tasks where tep_role is 'TASK_FOREGROUND_APPLICATION = 1'
        if (task_role == 1):
            pval = GetProcFromTask(t)
            print(GetTaskSummary(t), GetProcSummary(pval), GetTaskRoleSummary(t))

# EndMacro: showcurrentforegroundapps

# Macro: showallthreadgroups

@lldb_type_summary(['struct thread_group *', 'thread_group *'])
@header("{0: <20s} {1: <5s} {2: <16s} {3: <5s} {4: <8s} {5: <20s}".format("thread_group", "id", "name", "refc", "flags", "recommendation"))
def GetThreadGroupSummary(tg):
    if unsigned(tg) == 0:
        return '{0: <#020x} {1: <5d} {2: <16s} {3: <5d} {4: <8s} {5: <20d}'.format(0, -1, "", -1, "", -1)
    out_string = ""
    format_string = '{0: <#020x} {1: <5d} {2: <16s} {3: <5d} {4: <8s} {5: <20d}'
    tg_flags = ''
    if (tg.tg_flags & 0x1):
        tg_flags += 'E'
    if (tg.tg_flags & 0x2):
        tg_flags += 'A'
    if (tg.tg_flags & 0x4):
        tg_flags += 'C'
    if (tg.tg_flags & 0x100):
        tg_flags += 'U'
    out_string += format_string.format(tg, tg.tg_id, tg.tg_name, tg.tg_refcount.ref_count, tg_flags, tg.tg_recommendation)
    return out_string

@lldb_command('showallthreadgroups')
def ShowAllThreadGroups(cmd_args=None):
    """  Print a summary listing of all thread groups
    """
    global kern
    print(GetThreadGroupSummary.header)
    for tg in kern.thread_groups:
        print(GetThreadGroupSummary(tg))

# EndMacro: showallthreadgroups

# Macro: showtaskcoalitions

@lldb_command('showtaskcoalitions', 'F:')
def ShowTaskCoalitions(cmd_args=None, cmd_options={}):
    """
    """
    task_list = []
    if "-F" in cmd_options:
        task_list = FindTasksByName(cmd_options["-F"])
    elif cmd_args:
        t = kern.GetValueFromAddress(cmd_args[0], 'task *')
        task_list.append(t)
    else:
        raise ArgumentError("No arguments passed")

    if len(task_list) > 0:
        print(GetCoalitionSummary.header)
    for task in task_list:
        print(GetCoalitionSummary(task.coalition[0]))
        print(GetCoalitionSummary(task.coalition[1]))

# EndMacro: showtaskcoalitions

INVALID_PROC_SUMMARY = "Process is not valid."

@lldb_type_summary(['proc', 'proc *'])
@header("{0: >6s}   {1: <18s} {2: >11s} {3: ^10s} {4: <32s}".format("pid", "process", "io_policy", "wq_state", "command"))
def GetProcSummary(proc: Optional[value]) -> str:
    """ Summarize the process data. 
        params:
          proc : value - value representaitng a proc * in kernel
        returns:
          str - string summary of the process.
    """
    if proc is None:
        return INVALID_PROC_SUMMARY

    out_string = ""
    format_string= "{0: >6d}   {1: <#018x} {2: >11s} {3: >2d} {4: >2d} {5: >2d}   {6: <32s}"
    pval = proc.GetSBValue()
    #code.interact(local=locals())
    if str(pval.GetType()) != str(gettype('proc *')) :
        return "Unknown type " + str(pval.GetType()) + " " + str(hex(proc))
    pid = int(GetProcPID(proc))
    proc_addr = int(hex(proc), 16)
    proc_rage_str = ""
    if int(proc.p_lflag) & 0x400000 :
        proc_rage_str = "RAGE"
    
    task = GetTaskFromProc(proc)
    if task is None:
        return "Process is not associated with a Task"
    
    io_policy_str = ""
    
    if int(task.effective_policy.tep_darwinbg) != 0:
        io_policy_str += "B"
    if int(task.effective_policy.tep_lowpri_cpu) != 0:
        io_policy_str += "L"
    
    if int(task.effective_policy.tep_io_tier) != 0:
        io_policy_str += "T"
    if int(task.effective_policy.tep_io_passive) != 0:
        io_policy_str += "P"
    if int(task.effective_policy.tep_terminated) != 0:
        io_policy_str += "D"
    
    if int(task.effective_policy.tep_latency_qos) != 0:
        io_policy_str += "Q"
    if int(task.effective_policy.tep_sup_active) != 0:
        io_policy_str += "A"

    if int(proc.p_refcount) & GetEnumValue("proc_ref_bits_t::P_REF_SHADOW") :
        io_policy_str += "S"
    
    
    try:
        work_queue = proc.p_wqptr
        if proc.p_wqptr != 0 :
            wq_num_threads = int(work_queue.wq_nthreads)
            wq_idle_threads = int(work_queue.wq_thidlecount)
            wq_req_threads = int(work_queue.wq_reqcount)
        else:
            wq_num_threads = 0
            wq_idle_threads = 0
            wq_req_threads = 0
    except:
        wq_num_threads = -1
        wq_idle_threads = -1
        wq_req_threads = -1
    process_name = GetProcName(proc)
    if process_name == 'xpcproxy':
        for thread in IterateQueue(task.threads, 'thread *', 'task_threads'):
            thread_name = GetThreadName(thread)
            if thread_name:
                process_name += ' (' + thread_name + ')'
                break
    out_string += format_string.format(pid, proc_addr, " ".join([proc_rage_str, io_policy_str]), wq_num_threads, wq_idle_threads, wq_req_threads, process_name)
    return out_string

@lldb_type_summary(['tty_dev_t', 'tty_dev_t *'])
@header("{0: <20s} {1: <10s} {2: <10s} {3: <15s} {4: <15s} {5: <15s} {6: <15s}".format("tty_dev","primary", "replica", "open", "free", "name", "revoke"))
def GetTTYDevSummary(tty_dev):
    """ Summarizes the important fields in tty_dev_t structure.
        params: tty_dev: value - value object representing a tty_dev_t in kernel
        returns: str - summary of the tty_dev
    """
    out_string = ""
    format_string = "{0: <#020x} {1: <#010x} {2: <#010x} {3: <15s} {4: <15s} {5: <15s} {6: <15s}" 
    open_fn = kern.Symbolicate(int(hex(tty_dev.open), 16))
    free_fn = kern.Symbolicate(int(hex(tty_dev.free), 16))
    name_fn = kern.Symbolicate(int(hex(tty_dev.name), 16))
    revoke_fn = kern.Symbolicate(int(hex(tty_dev.revoke), 16))
    out_string += format_string.format(tty_dev, tty_dev.primary, tty_dev.replica, open_fn, free_fn, name_fn, revoke_fn)
    return out_string

# Macro: showtask

@lldb_command('showtask', 'F:') 
def ShowTask(cmd_args=None, cmd_options={}):
    """  Routine to print a summary listing of given task
         Usage: showtask <address of task>
         or   : showtask -F <name of task>  
    """
    task_list = []
    if "-F" in cmd_options:
        task_list = FindTasksByName(cmd_options['-F'])
    else:
        if cmd_args is None or len(cmd_args) == 0:
            raise ArgumentError("Invalid arguments passed.")

        task_address = ArgumentStringToInt(cmd_args[0])
        tval = addressof(kern.CreateValueFromAddress(task_address, 'task'))
        if not tval:
            raise ArgumentError("Unknown arguments: {:s}".format(cmd_args[0]))

        task_list.append(tval)
    
    for tval in task_list:
        print(GetTaskSummary.header + " " + GetProcSummary.header)
        pval = GetProcFromTask(tval)
        print(GetTaskSummary(tval) +" "+ GetProcSummary(pval))

# EndMacro: showtask

# Macro: showpid

@lldb_command('showpid') 
def ShowPid(cmd_args=None):
    """  Routine to print a summary listing of task corresponding to given pid
         Usage: showpid <pid value>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")
    pidval = ArgumentStringToInt(cmd_args[0])
    for t in kern.tasks:
        pval = GetProcFromTask(t)
        if pval is not None and GetProcPID(pval) == pidval:
            print(GetTaskSummary.header + " " + GetProcSummary.header)
            print(GetTaskSummary(t) + " " + GetProcSummary(pval))
            break

# EndMacro: showpid

# Macro: showproc

@lldb_command('showproc') 
def ShowProc(cmd_args=None):
    """  Routine to print a summary listing of task corresponding to given proc
         Usage: showproc <address of proc>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")
    pval = kern.GetValueFromAddress(cmd_args[0], 'proc *')
    if not pval:
        print("unknown arguments:", str(cmd_args))
        return False
    print(GetTaskSummary.header + " " + GetProcSummary.header)
    tval = GetTaskFromProc(pval)
    print(GetTaskSummary(tval) + " " + GetProcSummary(pval))

# EndMacro: showproc

# Macro: showprocinfo

@lldb_command('showprocinfo') 
def ShowProcInfo(cmd_args=None):
    """  Routine to display name, pid, parent & task for the given proc address
         It also shows the Cred, Flags and state of the process
         Usage: showprocinfo <address of proc>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")
    pval = kern.GetValueFromAddress(cmd_args[0], 'proc *')
    if not pval:
        print("unknown arguments:", str(cmd_args))
        return False
    print(GetProcInfo(pval))

# EndMacro: showprocinfo

#Macro: showprocfiles

@lldb_command('showprocfiles')
def ShowProcFiles(cmd_args=None):
    """ Given a proc_t pointer, display the list of open file descriptors for the referenced process.
        Usage: showprocfiles <proc_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    proc = kern.GetValueFromAddress(cmd_args[0], 'proc_t')
    proc_filedesc = addressof(proc.p_fd)
    proc_ofiles = proc_filedesc.fd_ofiles
    if unsigned(proc_ofiles) == 0:
        print('No open files for proc {0: <s}'.format(cmd_args[0]))
        return
    print("{0: <5s} {1: <18s} {2: <10s} {3: <8s} {4: <18s} {5: <64s}".format('FD', 'FILEGLOB', 'FG_FLAGS', 'FG_TYPE', 'FG_DATA','INFO'))
    print("{0:-<5s} {0:-<18s} {0:-<10s} {0:-<8s} {0:-<18s} {0:-<64s}".format(""))

    for fd in range(0, unsigned(proc_filedesc.fd_afterlast)):
        if unsigned(proc_ofiles[fd]) != 0:
            out_str = ''
            proc_fd_flags = proc_ofiles[fd].fp_flags
            proc_fd_fglob = proc_ofiles[fd].fp_glob
            proc_fd_fglob_fg_data = Cast(proc_fd_fglob.fg_data, 'void *')
            out_str += "{0: <5d} ".format(fd)
            out_str += "{0: <#18x} ".format(unsigned(proc_fd_fglob))
            out_str += "0x{0:0>8x} ".format(unsigned(proc_fd_flags))
            proc_fd_ftype = unsigned(proc_fd_fglob.fg_ops.fo_type)
            if proc_fd_ftype in xnudefines.filetype_strings:
                out_str += "{0: <8s} ".format(xnudefines.filetype_strings[proc_fd_ftype])
            else:
                out_str += "?: {0: <5d} ".format(proc_fd_ftype)
            out_str += "{0: <#18x} ".format(unsigned(proc_fd_fglob_fg_data))
            if proc_fd_ftype == 1:
                fd_name = Cast(proc_fd_fglob_fg_data, 'struct vnode *').v_name
                out_str += "{0: <64s}".format(fd_name)
            out_str += "\n"
            print(out_str)

#EndMacro: showprocfiles

#Macro: showtty

@lldb_command('showtty')
def ShowTTY(cmd_args=None):
    """ Display information about a struct tty
        Usage: showtty <tty struct>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    
    tty = kern.GetValueFromAddress(cmd_args[0], 'struct tty *')
    print("TTY structure at:              {0: <s}".format(cmd_args[0]))
    print("Last input to raw queue:       {0: <#18x} \"{1: <s}\"".format(unsigned(tty.t_rawq.c_cs), tty.t_rawq.c_cs))
    print("Last input to canonical queue: {0: <#18x} \"{1: <s}\"".format(unsigned(tty.t_canq.c_cs), tty.t_canq.c_cs))
    print("Last output data:              {0: <#18x} \"{1: <s}\"".format(unsigned(tty.t_outq.c_cs), tty.t_outq.c_cs))
    tty_state_info = [
                  ['', 'TS_SO_OLOWAT (Wake up when output <= low water)'],
                  ['- (synchronous I/O mode)', 'TS_ASYNC (async I/O mode)'],
                  ['', 'TS_BUSY (Draining output)'],
                  ['- (Carrier is NOT present)', 'TS_CARR_ON (Carrier is present)'],
                  ['', 'TS_FLUSH (Outq has been flushed during DMA)'],
                  ['- (Open has NOT completed)', 'TS_ISOPEN (Open has completed)'],
                  ['', 'TS_TBLOCK (Further input blocked)'],
                  ['', 'TS_TIMEOUT (Wait for output char processing)'],
                  ['', 'TS_TTSTOP (Output paused)'],
                  ['', 'TS_WOPEN (Open in progress)'],
                  ['', 'TS_XCLUDE (Tty requires exclusivity)'],
                  ['', 'TS_BKSL (State for lowercase \\ work)'],
                  ['', 'TS_CNTTB (Counting tab width, ignore FLUSHO)'],
                  ['', 'TS_ERASE (Within a \\.../ for PRTRUB)'],
                  ['', 'TS_LNCH (Next character is literal)'],
                  ['', 'TS_TYPEN (Retyping suspended input (PENDIN))'],
                  ['', 'TS_CAN_BYPASS_L_RINT (Device in "raw" mode)'],
                  ['- (Connection NOT open)', 'TS_CONNECTED (Connection open)'],
                  ['', 'TS_SNOOP (Device is being snooped on)'],
                  ['', 'TS_SO_OCOMPLETE (Wake up when output completes)'],
                  ['', 'TS_ZOMBIE (Connection lost)'],
                  ['', 'TS_CAR_OFLOW (For MDMBUF - handle in driver)'],
                  ['', 'TS_CTS_OFLOW (For CCTS_OFLOW - handle in driver)'],
                  ['', 'TS_DSR_OFLOW (For CDSR_OFLOW - handle in driver)']
                ]
    index = 0
    mask = 0x1
    tty_state = unsigned(tty.t_state)
    print("State:")
    while index < 24:
        if tty_state & mask != 0:
            if len(tty_state_info[index][1]) > 0:
                print('\t' + tty_state_info[index][1])
        else:
            if len(tty_state_info[index][0]) > 0:
                print('\t' + tty_state_info[index][0])
        index += 1
        mask = mask << 1
    print("Flags:                    0x{0:0>8x}".format(unsigned(tty.t_flags)))
    print("Foreground Process Group: 0x{0:0>16x}".format(unsigned(tty.t_pgrp)))
    print("Enclosing session:        0x{0:0>16x}".format(unsigned(tty.t_session)))
    print("Termios:")
    print("\tInput Flags:   0x{0:0>8x}".format(unsigned(tty.t_termios.c_iflag)))
    print("\tOutput Flags:  0x{0:0>8x}".format(unsigned(tty.t_termios.c_oflag)))
    print("\tControl Flags: 0x{0:0>8x}".format(unsigned(tty.t_termios.c_cflag)))
    print("\tLocal Flags:   0x{0:0>8x}".format(unsigned(tty.t_termios.c_lflag)))
    print("\tInput Speed:   {0: <8d}".format(tty.t_termios.c_ispeed))
    print("\tOutput Speed:  {0: <8d}".format(tty.t_termios.c_ospeed))
    print("High Watermark: {0: <d} bytes".format(tty.t_hiwat))
    print("Low Watermark : {0: <d} bytes".format(tty.t_lowat))

#EndMacro: showtty

#Macro showallttydevs

@lldb_command('showallttydevs')
def ShowAllTTYDevs(cmd_args=[], cmd_options={}):
    """ Show a list of ttydevs registered in the system.
        Usage:
        (lldb)showallttydevs
    """
    tty_dev_head = kern.globals.tty_dev_head
    tty_dev = tty_dev_head
    print(GetTTYDevSummary.header)
    while unsigned(tty_dev) != 0:
        print(GetTTYDevSummary(tty_dev))
        tty_dev = tty_dev.next
    return ""

#EndMacro: showallttydevs

#Macro: dumpthread_terminate_queue

@lldb_command('dumpthread_terminate_queue', fancy=True)
def DumpThreadTerminateQueue(cmd_args=None, cmd_options={}, O=None):
    """ Displays the contents of the specified call_entry queue.
        Usage: dumpthread_terminate_queue 
    """
    
    count = 0
    with O.table(GetThreadSummary.header):
        for th in IterateMPSCQueue(addressof(kern.globals.thread_terminate_queue.mpd_queue), 'struct thread', 'mpsc_links'):
            print(GetThreadSummary(th, O=O))
            count += 1
    print("{0: <d} entries!".format(count))

#EndMacro: dumpthread_terminate_queue

#Macro: dumpcrashed_thread_queue

@lldb_command('dumpcrashed_thread_queue', fancy=True)
def DumpCrashedThreadsQueue(cmd_args=None, cmd_options={}, O=None):
    """ Displays the contents of the specified call_entry queue.
        Usage: dumpcrashed_thread_queue 
    """
    
    count = 0
    with O.table(GetThreadSummary.header):
        for th in IterateQueue(addressof(kern.globals.crashed_threads_queue), 'struct thread *',  'q_link'):
            print(GetThreadSummary(th), O=O)
            count += 1
    print("{0: <d} entries!".format(count))

#EndMacro: dumpcrashed_thread_queue

#Macro: dumpcallqueue

@lldb_command('dumpcallqueue')
def DumpCallQueue(cmd_args=None):
    """ Displays the contents of the specified call_entry queue.
        Usage: dumpcallqueue <queue_head_t *>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Invalid arguments")

    print("{0: <18s} {1: <18s} {2: <18s} {3: <64s} {4: <18s}".format('CALL_ENTRY', 'PARAM0', 'PARAM1', 'DEADLINE', 'FUNC'))
    callhead = kern.GetValueFromAddress(cmd_args[0], 'queue_head_t *')
    count = 0
    for callentry in IterateQueue(callhead, 'struct call_entry *',  'q_link'):
        print("{0: <#18x} {1: <#18x} {2: <#18x} {3: <64d} {4: <#18x}".format(
              unsigned(callentry), unsigned(callentry.param0), unsigned(callentry.param1), 
              unsigned(callentry.deadline), unsigned(callentry.func)))
        count += 1
    print("{0: <d} entries!".format(count))

#EndMacro: dumpcallqueue

@lldb_command('showalltasklogicalwrites')
def ShowAllTaskIOStats(cmd_args=None):
    """ Commad to print I/O stats for all tasks
    """
    print("{0: <20s} {1: <20s} {2: <20s} {3: <20s} {4: <20s} {5: <20s} {6: <20s} {7: <20s} {8: <20s} {9: <32}".format("task", "Immediate Writes", "Deferred Writes", "Invalidated Writes", "Metadata Writes", "Immediate Writes to External", "Deferred Writes to External", "Invalidated Writes to External", "Metadata Writes to External", "name"))
    for t in kern.tasks:
        pval = GetProcFromTask(t)
        print("{0: <#18x} {1: >20d} {2: >20d} {3: >20d} {4: >20d}  {5: <20s} {6: <20s} {7: <20s} {8: <20s} {9: <20s}".format(t,
            t.task_writes_counters_internal.task_immediate_writes, 
            t.task_writes_counters_internal.task_deferred_writes,
            t.task_writes_counters_internal.task_invalidated_writes,
            t.task_writes_counters_internal.task_metadata_writes,
            t.task_writes_counters_external.task_immediate_writes, 
            t.task_writes_counters_external.task_deferred_writes,
            t.task_writes_counters_external.task_invalidated_writes,
            t.task_writes_counters_external.task_metadata_writes,
            GetProcName(pval)))


@lldb_command('showalltasks','C R', fancy=True)
def ShowAllTasks(cmd_args=None, cmd_options={}, O=None):
    """  Routine to print a summary listing of all the tasks
         wq_state -> reports "number of workq threads", "number of scheduled workq threads", "number of pending work items"
         if "number of pending work items" seems stuck at non-zero, it may indicate that the workqueue mechanism is hung
         io_policy -> RAGE  - rapid aging of vnodes requested
                     NORM  - normal I/O explicitly requested (this is the default)
                     PASS  - passive I/O requested (i.e. I/Os do not affect throttling decisions)
                     THROT - throttled I/O requested (i.e. thread/task may be throttled after each I/O completes)
         Usage: (lldb) showalltasks -C  : describe the corpse structure
         Usage: (lldb) showalltasks -R  : describe the task role app status
    """
    global kern
    extra_hdr = ''
    showcorpse = False
    showrole = False
    if '-C' in cmd_options:
        showcorpse = True
        extra_hdr += " " + GetKCDataSummary.header

    if '-R' in cmd_options:
        showrole = True
        extra_hdr += " " + GetTaskRoleSummary.header

    with O.table(GetTaskSummary.header + extra_hdr + " " + GetProcSummary.header):
        for t in kern.tasks:
            pval = GetProcFromTask(t)
            print(GetTaskSummary(t, showcorpse) + " " + (GetTaskRoleSummary(t) + " " if showrole else "") 
                  + GetProcSummary(pval))

    ZombTasks()

def TaskForPmapHelper(pmap) -> Optional[value]:
    """ Given a pmap pointer, return the task pointer which contains that
        address space.

        pmap: PMAP pointer whose task to find.
    """
    for tasklist in [kern.tasks, kern.terminated_tasks]:
        for task in tasklist:
            if kern.GetValueFromAddress(unsigned(task.map.pmap), 'pmap_t') == pmap:
                return task

    return None

@lldb_command('taskforpmap')
def TaskForPmap(cmd_args=None):
    """ Find the task whose pmap corresponds to <pmap>.
        Syntax: (lldb) taskforpmap <pmap>
            Multiple -v's can be specified for increased verbosity
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Too few arguments to taskforpmap.")
    pmap = kern.GetValueFromAddress(cmd_args[0], 'pmap_t')
    task = TaskForPmapHelper(pmap)

    if task is None:
        print("Couldn't find task for pmap {:#x}".format(pmap))
        return

    print(GetTaskSummary.header + " " + GetProcSummary.header)
    pval = GetProcFromTask(task)
    print(GetTaskSummary(task) + " " + GetProcSummary(pval))

@lldb_command('showterminatedtasks') 
def ShowTerminatedTasks(cmd_args=None):
    """  Routine to print a summary listing of all the terminated tasks
         wq_state -> reports "number of workq threads", "number of scheduled workq threads", "number of pending work items"
         if "number of pending work items" seems stuck at non-zero, it may indicate that the workqueue mechanism is hung
         io_policy -> RAGE  - rapid aging of vnodes requested
                     NORM  - normal I/O explicitly requested (this is the default)
                     PASS  - passive I/O requested (i.e. I/Os do not affect throttling decisions)
                     THROT - throttled I/O requested (i.e. thread/task may be throttled after each I/O completes)
        syntax: (lldb)showallterminatedtasks
    """
    global kern
    print(GetTaskSummary.header + " " + GetProcSummary.header)
    for t in kern.terminated_tasks:

        # If the task has been terminated it's likely that the process is
        # gone too. If there is no proc it may still be possible to find
        # the original proc name.
        pval = GetProcFromTask(t)
        if pval is not None:
            psummary = GetProcSummary(pval)
        else:
            name = GetProcNameForTask(t);
            pslen = GetProcSummary.header.find("command");
            psummary = "{0: <{indent}} {1: <s}".format("", name, indent = pslen - 1)

        print(GetTaskSummary(t) + " " + psummary)

    return True

# Macro: showtaskstacks

def TokenExistsInStack(thread, regex):
    thread_val = GetLLDBThreadForKernelThread(thread)
    for frame in thread_val.frames:
        if frame.GetFunction():
            func_name = frame.GetFunctionName()
            func_arguments = frame.arguments
            matching_argument = any(
                True if regex.search(str(arg.type)) or regex.search(str(arg.value)) else False
                for arg in func_arguments
            )
            if regex.search(func_name) or matching_argument:
                return True
    return False

def ShowTaskStacks(task, O=None, regex=None):
    """ Print a task with summary and stack information for each of its threads 
    """
    global kern
    first = True

    for th in IterateQueue(task.threads, 'thread *', 'task_threads'):
        if regex is None or TokenExistsInStack(th, regex):
            if first:
                print(GetTaskSummary.header + " " + GetProcSummary.header)
                pval = GetProcFromTask(task)
                print(GetTaskSummary(task) + " " + GetProcSummary(pval))
                first = False
            with O.table(GetThreadSummary.header, indent=True):
                print(GetThreadSummary(th, O=O))
                print(GetThreadBackTrace(th, prefix="    ") + "\n")


def FindTasksByName(searchstr, ignore_case=True):
    """ Search the list of tasks by name. 
        params:
            searchstr: str - a regex like string to search for task
            ignore_case: bool - If False then exact matching will be enforced
        returns:
            [] - array of task object. Empty if not found any
    """
    re_options = 0   
    if ignore_case:
        re_options = re.IGNORECASE
    search_regex = re.compile(searchstr, re_options)
    retval = []
    for t in kern.tasks: 
        pval = GetProcFromTask(t)
        process_name = "{:s}".format(GetProcName(pval))
        if search_regex.search(process_name):
            retval.append(t)
    return retval

@lldb_command('showtaskstacks', 'F:', fancy=True)
def ShowTaskStacksCmdHelper(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print out the stack for each thread in a task
        Usage: showtaskstacks <0xaddress of task>
           or: showtaskstacks -F launchd   
    """

    if "-F" in cmd_options:
        find_task_str = cmd_options["-F"]
        task_list = FindTasksByName(find_task_str)
        for tval in task_list:
            ShowTaskStacks(tval, O=O)
        return
    
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")

    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        raise ArgumentError("unknown arguments: {:s}".format(str(cmd_args)))
    else:
        ShowTaskStacks(tval, O=O)

# EndMacro: showtaskstacks

def CheckTaskProcRefs(task, proc, O=None):
    btlib = kmemory.BTLibrary.get_shared()

    for thread in IterateQueue(task.threads, 'thread *', 'task_threads'):
        uthread = GetBSDThread(thread)
        refcount = int(uthread.uu_proc_refcount)
        uu_ref_info = uthread.uu_proc_ref_info
        if int(uu_ref_info) == 0:
            continue
        uu_ref_index = int(uu_ref_info.upri_pindex)
        if refcount == 0:
            continue
        for ref in range(0, uu_ref_index):
            if unsigned(uu_ref_info.upri_proc_ps[ref]) == unsigned(proc):
                print(GetTaskSummary.header + " " + GetProcSummary.header)
                pval = GetProcFromTask(task)
                print(GetTaskSummary(task) + " " + GetProcSummary(pval))
                with O.table(GetThreadSummary.header, indent=True):
                    print(GetThreadSummary(thread, O=O))

                bts = btlib.get_stack(unsigned(uu_ref_info.upri_proc_stacks[ref]))
                print(*bts.symbolicated_frames(), sep="\n")

@lldb_command('showprocrefs', fancy=True)
def ShowProcRefs(cmd_args=None, cmd_options={}, O=None):
    """ Display information on threads/BTs that could be holding a reference on the specified proc
        NOTE: We can't say affirmatively if any of these references are still held since
              there's no way to pair references with drop-refs in the current infrastructure.
        Usage: showprocrefs <proc>
    """
    if cmd_args is None or len(cmd_args) == 0:
         raise ArgumentError("No arguments passed")

    proc = kern.GetValueFromAddress(cmd_args[0], 'proc *')

    for t in kern.tasks:
        CheckTaskProcRefs(t, proc, O=O)
    for t in kern.terminated_tasks:
        CheckTaskProcRefs(t, proc, O=O)

@lldb_command('showallthreads', fancy=True)
def ShowAllThreads(cmd_args=None, cmd_options={}, O=None):
    """ Display info about all threads in the system
    """

    # Terminated threads get prefixed with a 'T'
    def ShowTaskTerminatedThreads(task, O=O):
        tlist = tmap.get(unsigned(task), [])
        for thval in tlist:
            print("T\t" + GetThreadSummary(thval, O=O))

    # Task -> [thread, ..] map of terminated threads
    tmap = defaultdict(list)
    for thr in kern.terminated_threads:
        tmap[unsigned(thr.t_tro.tro_task)].append(thr)

    for t in kern.tasks:
        ShowTaskThreads([str(int(t))], O=O)
        ShowTaskTerminatedThreads(t, O=O)
        print(" \n")

    for t in kern.terminated_tasks:
        print("Terminated: \n")
        ShowTaskThreads([str(int(t))], O=O)
        ShowTaskTerminatedThreads(t, O=O)
        print(" \n")

    return

@lldb_command('showterminatedthreads', fancy=True)
def ShowTerminatedThreads(cmd_args=None, cmd_options={}, O=None):
    """ Display info about all terminated threads in the system
    """

    with O.table(GetThreadSummary.header, indent=True):
        for t in kern.terminated_threads:
            print(GetThreadSummary(t, O=O))


@lldb_command('showtaskthreads', "F:", fancy=True)
def ShowTaskThreads(cmd_args = None, cmd_options={}, O=None):
    """ List the threads of a task.
        Usage: showtaskthreads <task-ptr>
           or: showtaskthreads -F <name>
    """
    task_list = []

    if "-F" in cmd_options:
        task_list = FindTasksByName(cmd_options["-F"])
    elif cmd_args:
        task_addr = ArgumentStringToInt(cmd_args[0])
        t = addressof(kern.CreateValueFromAddress(task_addr, 'task'))
        task_list = [t]
    else:
        raise ArgumentError("No arguments passed")
    
    for task in task_list:
        print(GetTaskSummary.header + " " + GetProcSummary.header)
        pval = GetProcFromTask(task)
        print(GetTaskSummary(task) + " " + GetProcSummary(pval))
        with O.table(GetThreadSummary.header, indent=True):
            for thval in IterateQueue(task.threads, 'thread *', 'task_threads'):
                print(GetThreadSummary(thval, O=O))
    return

@lldb_command('showact', fancy=True)
def ShowAct(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print out the state of a specific thread.
        usage: showact <activation> 
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")
    threadval = kern.GetValueFromAddress(cmd_args[0], 'thread *')
    with O.table(GetThreadSummary.header):
        print(GetThreadSummary(threadval, O=O))

@lldb_command('showactstack', fancy=True)
def ShowActStack(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print out the stack of a specific thread.
        usage:  showactstack <activation> 
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")
    threadval = kern.GetValueFromAddress(cmd_args[0], 'thread *')
    with O.table(GetThreadSummary.header):
        print(GetThreadSummary(threadval, O=O))
    print(GetThreadBackTrace(threadval, prefix="\t"))
    return

@lldb_command('switchtoact', fancy=True)
def SwitchToAct(cmd_args=None, cmd_options={}, O=None):
    """ Switch to different context specified by activation
    This command allows gdb to examine the execution context and call
    stack for the specified activation. For example, to view the backtrace
    for an activation issue "switchtoact <address>", followed by "bt".
    Before resuming execution, issue a "resetctx" command, to
    return to the original execution context.
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")
    thval = kern.GetValueFromAddress(cmd_args[0], 'thread *')
    lldbthread = GetLLDBThreadForKernelThread(thval)
    with O.table(GetThreadSummary.header):
        print(GetThreadSummary(thval, O=O))
    LazyTarget.GetProcess().selected_thread = lldbthread
    if not LazyTarget.GetProcess().SetSelectedThread(lldbthread):
        print("Failed to switch thread.")
    return

@lldb_command('switchtoregs')
def SwitchToRegs(cmd_args=None):
    """ Routine to switch to a register state.
        Usage: (lldb) switchtoregs <struct arm_saved_state[64] *>
        This command creates a fake thread in lldb with the saved register state.
        Note: This command ONLY works for ARM based kernel setup.
    """
    
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")

    lldb_process = LazyTarget.GetProcess()
    
    saved_state = ArgumentStringToInt(cmd_args[0])
    # any change to this logic requires change in operating_system.py as well
    fake_thread_id = 0xdead0000 | (saved_state & ~0xffff0000)
    fake_thread_id = fake_thread_id & 0xdeadffff
    lldb_process.CreateOSPluginThread(0xdeadbeef, saved_state)
    lldbthread = lldb_process.GetThreadByID(int(fake_thread_id))
    
    if not lldbthread.IsValid():
        print("Failed to create thread")
        return

    lldb_process.selected_thread = lldbthread
    if not lldb_process.SetSelectedThread(lldbthread):
        print("Failed to switch thread")
    print("Switched to Fake thread created from register state at {:#x}".format(
            saved_state))

# Macro: showcallchains
CallChainNode = namedtuple("CallChainNode", "callers threads")

def GatherCallChainsDFS(cur_node: CallChainNode, call_chains, cur_path):
    if cur_node.threads:
        call_chain = " <- ".join(cur_path) 
        call_chains[call_chain] = cur_node.threads

    for next_func_name, next_node in cur_node.callers.items():
        cur_path.append(next_func_name)
        GatherCallChainsDFS(next_node, call_chains, cur_path)
        cur_path.pop()


def GetCallChains(filter_regex) -> dict[str, list[str]]:
    ## Filter threads and build call graph
    root = CallChainNode({"root": CallChainNode({}, [])}, [])

    zomb_tasks = [t for proc in kern.zombprocs if (t := GetTaskFromProc(proc)) is not None]
    for t in kern.tasks + zomb_tasks:
        for th in IterateQueue(t.threads, 'thread *', 'task_threads'):
            thread_val = GetLLDBThreadForKernelThread(th)
            cur_node = root
            prev_func_name = "root"
            matched = False

            for frame in thread_val.frames:
                if frame.GetFunction():
                    func_name = frame.GetFunctionName()
                    func_arguments = frame.arguments
                    matching_argument = any(
                        True if filter_regex.match(str(arg.type)) or filter_regex.match(str(arg.value)) else False
                        for arg in func_arguments
                        )
                    if filter_regex.match(func_name) or matching_argument:
                        matched = True

                        callers = cur_node.callers[prev_func_name].callers
                        callers[func_name] = callers.get(func_name, CallChainNode({}, []))

                        cur_node = cur_node.callers[prev_func_name]
                        prev_func_name = func_name

            if matched:
                cur_node.callers[prev_func_name].threads.append(th)

    ## gather call chains
    call_chains: dict[str, list[str]] = {}
    GatherCallChainsDFS(root.callers["root"], call_chains, [])

    return call_chains

CallChainThreadInfo = namedtuple('CallChainThreadInfo', ['hex', 'state', 'base', 'pri', 'since_off', 'wait_evt', 'wait_evt_sym', 'thread_name', 'task_name'])   

@lldb_command('showcallchains', fancy=True)
def ShowCallChains(cmd_args=None, cmd_options={}, O=None):
    """Routine to print out thread IDs, bucketized by function call chains

    Usage: showcallchains <regex>
        The regex filters function names. Function names that don't match the regex are ignored.
    """
    
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed.")

    show_call_chain(cmd_args[0],O)

def show_call_chain(param, O=None):

    try:
        regex = re.compile(param)
    except:
        raise ArgumentError("Invalid predicate regex passed: {}".format(param[0]))
        
    call_chains = GetCallChains(regex)
    
    summary_str = "{info.hex: <20s} {info.state: <8s} {info.base: <6s} {info.pri: <10s} {info.since_off: <20s} {info.wait_evt: <20s} {info.wait_evt_sym: <20s} {info.thread_name: <20.20s} {info.task_name: <20s}" 
    header = summary_str.format(info=CallChainThreadInfo('thread', 'state', 'base', 'pri', 'since-off (us)', 'wait_evt', 'wait_evt_sym', 'thread_name', 'task_name')) 

    ## sort desc by time_since_off
    from scheduler import GetSchedMostRecentDispatch
    most_recent_dispatch = GetSchedMostRecentDispatch(False)
    def GetTimeSinceOff(th):
        last_off = th.last_run_time
        time_since_off_abs = unsigned(most_recent_dispatch - last_off)
        return time_since_off_abs
    
    for call_chain, threads in call_chains.copy().items():
        call_chains[call_chain] = sorted(
                                        zip(threads, (GetTimeSinceOff(th) for th in threads)),
                                            reverse=True,
                                            key=lambda a: a[1]
                                  )
    
    ## print results
    for call_chain, threads in sorted(
                                        list(call_chains.items()), 
                                        key = lambda a: len(a[1])
                                    ):
        print("{0}, {1} thread{2}".format(call_chain, len(threads), len(threads) > 1 and "s" or ""))

        with O.table(header, indent=True):
            for th, time_since_off_abs in threads:
                thread_hex = '{:<#018x}'.format(th)
                base_priority = str(int(th.base_pri))
                sched_priority = str(int(th.sched_pri))
                
                state = int(th.state)
                state_str = ''
                mask = 0x1
                while mask <= LAST_THREAD_STATE:
                    state_str += THREAD_STATE_CHARS[int(state & mask)]
                    mask <<= 1
                if int(th.inspection):
                    state_str += 'C'

                wait_event_str = ''
                wait_event_str_sym = ''
                if state & 0x1: # WAIT
                    wait_event_str = '{:<#018x}'.format(unsigned(th.wait_event))
                    wait_event_str_sym = kern.Symbolicate(int(hex(th.wait_event), 16))
                
                time_since_off_us = "{:,}".format(kern.GetNanotimeFromAbstime(time_since_off_abs) / 1000.0)

                uthread = GetBSDThread(th)
                thread_name = GetThreadNameFromBSDThread(uthread)

                pval = GetProcFromTask(th.t_tro.tro_task)
                task_name = GetProcName(pval)

                info = CallChainThreadInfo(hex=thread_hex, state=state_str, base=base_priority, pri=sched_priority, since_off=time_since_off_us,  
                                           wait_evt=wait_event_str, wait_evt_sym=wait_event_str_sym, thread_name=thread_name, task_name=task_name)
                info_str = summary_str.format(info=info)

                print(O.format(info_str))
        print("")

    print("Summary:")
    print("{} different call chains".format(len(call_chains)))
# Endmacro showcallchains


# Macro: showallstacks
@lldb_command('showallstacks', "R:", fancy=True)
def ShowAllStacks(cmd_args=None, cmd_options={}, O=None):
    """Routine to print out the stack for each thread in the system.
       Usage: showallstacks [-R REGEX]
          -R    : Only show stacks with function names matching the provided regular expression
    """
    if "-R" in cmd_options:
        regex = re.compile(cmd_options['-R'])
    else:
        regex = None
    for t in kern.tasks:
        ShowTaskStacks(t, O=O, regex=regex)
        if regex is None:
            print(" \n")
    
    ShowZombStacks(O=O, regex=regex)
# EndMacro: showallstacks

# Macro: showcurrentstacks
@lldb_command('showcurrentstacks', fancy=True)
def ShowCurrentStacks(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print out the thread running on each cpu (incl. its stack)
    """
    processor_list = kern.GetGlobalVariable('processor_list')
    current_processor = processor_list
    while unsigned(current_processor) > 0:
        print("\n" + GetProcessorSummary(current_processor))
        active_thread = current_processor.active_thread
        if unsigned(active_thread) != 0:
            task_val = active_thread.t_tro.tro_task
            proc_val = GetProcFromTask(task_val)
            print(GetTaskSummary.header + " " + GetProcSummary.header)
            print(GetTaskSummary(task_val) + " " + GetProcSummary(proc_val))
            with O.table(GetThreadSummary.header, indent=True):
                print(GetThreadSummary(active_thread, O=O))
            print("\tBacktrace:")
            print(GetThreadBackTrace(active_thread, prefix="\t"))
        current_processor = current_processor.processor_list
    return
# EndMacro: showcurrentstacks

@lldb_command('showcurrentthreads', fancy=True)
def ShowCurrentThreads(cmd_args=None, cmd_options={}, O=None):
    """ Display info about threads running on each cpu """
    processor_list = kern.GetGlobalVariable('processor_list')
    current_processor = processor_list
    while unsigned(current_processor) > 0:
        print(GetProcessorSummary(current_processor))
        active_thread = current_processor.active_thread
        if unsigned(active_thread) != 0 :
            task_val = active_thread.t_tro.tro_task
            proc_val = GetProcFromTask(task_val)
            print(GetTaskSummary.header + " " + GetProcSummary.header)
            print(GetTaskSummary(task_val) + " " + GetProcSummary(proc_val))
            with O.table(GetThreadSummary.header, indent=True):
                print(GetThreadSummary(active_thread, O=O))
        current_processor = current_processor.processor_list
    return

def GetFullBackTrace(frame_addr, verbosity = vHUMAN, prefix = ""):
    """ Get backtrace across interrupt context. 
        params: frame_addr - int - address in memory which is a frame pointer (ie. rbp, r7)
                prefix - str - prefix for each line of output.
        
    """
    out_string = ""
    bt_count = 0
    frame_ptr = frame_addr
    previous_frame_ptr = 0
    while frame_ptr and frame_ptr != previous_frame_ptr and bt_count < 128:
        pc_val = kern.GetValueFromAddress(frame_ptr + kern.ptrsize,'uintptr_t *')
        pc_val = kern.StripKernelPAC(unsigned(dereference(pc_val)))
        out_string += prefix + GetSourceInformationForAddress(pc_val) + "\n"
        bt_count +=1
        previous_frame_ptr = frame_ptr
        frame_val = kern.GetValueFromAddress((frame_ptr), 'uintptr_t *')
        if unsigned(frame_val) == 0:
            break
        frame_ptr = unsigned(dereference(frame_val))
        
    return out_string

@lldb_command('fullbt')
def FullBackTrace(cmd_args=[]):
    """ Show full backtrace across the interrupt boundary.
        Syntax: fullbt <frame ptr>
        Example: fullbt  `$rbp` 
    """
    if len(cmd_args) < 1:
        raise ArgumentError()

    print(GetFullBackTrace(ArgumentStringToInt(cmd_args[0]), prefix="\t"))

@lldb_command('fullbtall', fancy=True)
def FullBackTraceAll(cmd_args=[], cmd_options={}, O=None):
    """ Show full backtrace across the interrupt boundary for threads running on all processors.
        Syntax: fullbtall
        Example: fullbtall
    """
    for processor in IterateLinkedList(kern.globals.processor_list, 'processor_list') :
        print("\n" + GetProcessorSummary(processor))
        active_thread = processor.active_thread
        if unsigned(active_thread) != 0 :
            task_val = active_thread.t_tro.tro_task
            proc_val = GetProcFromTask(task_val)
            print(GetTaskSummary.header + " " + GetProcSummary.header)
            print(GetTaskSummary(task_val) + " " + GetProcSummary(proc_val))
            with O.table(GetThreadSummary.header, indent=True):
                print(GetThreadSummary(active_thread, O=O))
            print("\tBacktrace:")
                
            ThreadVal = GetLLDBThreadForKernelThread(active_thread)

            FramePtr = ThreadVal.frames[0].GetFP()
            
            print(GetFullBackTrace(unsigned(FramePtr), prefix="\t"))
            

@lldb_command('symbolicate')
def SymbolicateAddress(cmd_args=[]):
    """ Symbolicate an address for symbol information from loaded symbols
        Example: "symbolicate 0xaddr" is equivalent to "output/a 0xaddr"
    """
    if len(cmd_args) < 1:
        print("Invalid address.\nSyntax: symbolicate <address>")
        return False
    print(GetSourceInformationForAddress(ArgumentStringToInt(cmd_args[0])))
    return True

@lldb_command('showinitchild')
def ShowInitChild(cmd_args=None):
    """ Routine to print out all processes in the system
        which are children of init process
    """
    headp = kern.globals.initproc.p_children
    for pp in IterateListEntry(headp, 'p_sibling'):
        print(GetProcInfo(pp))
    return

@lldb_command('showproctree')
def ShowProcTree(cmd_args=None):
    """ Routine to print the processes in the system in a hierarchical tree form. This routine does not print zombie processes.
        If no argument is given, showproctree will print all the processes in the system.
        If pid is specified, showproctree prints all the descendants of the indicated process
    """
    search_pid = 0
    if cmd_args:
        search_pid = ArgumentStringToInt(cmd_args[0])
    
    if search_pid < 0:
        raise ArgumentError("pid specified must be a positive number")
    
    hdr_format = "{0: <6s} {1: <14s} {2: <9s}\n"
    out_string = hdr_format.format("PID", "PROCESS", "POINTER")
    out_string += hdr_format.format('='*3, '='*7, '='*7)
    proc = GetProcForPid(search_pid)
    out_string += "{0: <6d} {1: <32s} [ {2: #019x} ]\n".format(
            proc.p_ppid, GetProcName(proc.p_pptr), unsigned(proc.p_pptr))
    out_string += "|--{0: <6d} {1: <32s} [ {2: #019x} ]\n".format(
            GetProcPID(proc), GetProcName(proc), unsigned(proc))
    print(out_string)
    ShowProcTreeRecurse(proc, "|  ")

def ShowProcTreeRecurse(proc, prefix=""):
    """ Prints descendants of a given proc in hierarchial tree form
        params:
            proc  : core.value representing a struct proc * in the kernel
        returns:
            str   : String containing info about a given proc and its descendants in tree form
    """
    if proc.p_childrencnt > 0:
        head_ptr = proc.p_children.lh_first
        
        for p in IterateListEntry(proc.p_children, 'p_sibling'):
            print(prefix + "|--{0: <6d} {1: <32s} [ {2: #019x} ]\n".format(
                    GetProcPID(p), GetProcName(p), unsigned(p)))
            ShowProcTreeRecurse(p, prefix + "|  ")

@lldb_command('showthreadfortid', fancy=True)
def ShowThreadForTid(cmd_args=None, O=None):
    """ The thread structure contains a unique thread_id value for each thread.
        This command is used to retrieve the address of the thread structure(thread_t)
        corresponding to a given thread_id.
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Please provide thread_t whose tid you'd like to look up")

    search_tid = ArgumentStringToInt(cmd_args[0])
    for taskp in kern.tasks:
        for actp in IterateQueue(taskp.threads, 'struct thread *', 'task_threads'):
            if search_tid == int(actp.thread_id):
                print("Found {0: #019x}".format(actp))
                with O.table(GetThreadSummary.header):
                    print(GetThreadSummary(actp, O=O))
                return
    print("Not a valid thread_id")

def GetProcessorSummary(processor):
    """ Internal function to print summary of processor
        params: processor - value representing struct processor * 
        return: str - representing the details of given processor
    """
    
    processor_state_str = "INVALID" 
    processor_state = int(processor.state)
    
    processor_states = {
                0: 'OFF_LINE',
                1: 'SHUTDOWN',
                2: 'START',
                3: 'PENDING_OFFLINE',
                4: 'IDLE',
                5: 'DISPATCHING',
                6: 'RUNNING'
                }
    
    if processor_state in processor_states:
        processor_state_str = "{0: <11s} ".format(processor_states[processor_state])

    processor_recommended_str = ""
    if int(processor.is_recommended) == 0:
        processor_recommended_str = " (not recommended)"

    ast = 0
    preemption_disable = 0
    preemption_disable_str = ""

    if kern.arch == 'x86_64':
        cpu_data = kern.globals.cpu_data_ptr[processor.cpu_id]
        if (cpu_data != 0) :
            ast = cpu_data.cpu_pending_ast
            preemption_disable = cpu_data.cpu_preemption_level
    # On arm64, it's kern.globals.CpuDataEntries[processor.cpu_id].cpu_data_vaddr
    # but LLDB can't find CpuDataEntries...

    ast_str = GetASTSummary(ast)

    if (preemption_disable != 0) :
        preemption_disable_str = "Preemption Disabled"
    
    processor_reasons = {
        0: '(REASON_NONE)',
        1: '(REASON_SYSTEM)',
        2: '(REASON_USER)',
        3: '(REASON_CLPC_SYSTEM)',
        4: '(REASON_CLPC_USER)'
    }
    
    processor_shutdown_reason_str = "";
    processor_shutdown_reason = int(processor.last_shutdown_reason)
    
    if processor_state in {0, 1, 3}:
        processor_shutdown_reason_str = processor_reasons[processor_shutdown_reason]

    out_str = "Processor {: <#018x} cpu_id {:>#4x} AST: {:<6s} State {:<s}{:<s}{:<s} {:<s}\n".format(
            processor, int(processor.cpu_id), ast_str, processor_state_str, processor_shutdown_reason_str,
            processor_recommended_str, preemption_disable_str)
    return out_str   

ledger_limit_infinity = (uint64_t(0x1).value << 63) - 1

def GetLedgerEntryIndex(template, name):
    i = 0
    lt_count = template.lt_cnt
    lt_entries = template.lt_entries

    while i != lt_count:
        if str(lt_entries[i].et_key) == name:
            return i
        i += 1
    return -1

def GetLedgerEntryWithTemplate(ledger_template, ledgerp, i):
    """ Internal function to get internals of a ledger entry (*not* a ledger itself)
        params: ledger_template - value representing struct ledger_template_t for the task or thread
                ledgerp - value representing ledger pointer
                i - index in ledger
        return: entry - entry dictionary
    """
    lf_refill_scheduled = 0x0400
    lf_tracking_max = 0x4000

    entry = {}

    et = ledger_template.lt_entries[i]
    entry["key"] = str(et.et_key)
    et_size = et.et_size
    if et_size == sizeof("struct ledger_entry_small"):
        les = ledgerp.l_entries[et.et_offset]
        entry["credit"] = unsigned(les.les_credit)
        entry["debit"] = 0
        entry["flags"] = int(les.les_flags)
        entry["limit"] = ledger_limit_infinity
    elif et_size == sizeof("struct ledger_entry"):
        le = cast(addressof(ledgerp.l_entries[et.et_offset]), "struct ledger_entry *")
        entry["credit"] = unsigned(le.le_credit)
        entry["debit"] = unsigned(le.le_debit)
        le_flags = int(le.le_flags)
        if (le_flags & lf_tracking_max):
            if hasattr(le._le._le_max, "le_interval_max"):
                entry["interval_max"] = unsigned(le._le._le_max.le_interval_max)
            entry["lifetime_max"] = unsigned(le._le._le_max.le_lifetime_max)

        entry["limit"] = unsigned(le.le_limit)

        if (le_flags & lf_refill_scheduled):
            entry["refill_period"] = unsigned(le._le.le_refill.le_refill_period)

        if (unsigned(le.le_warn_percent) < 65535):
            entry["warn_percent"] = unsigned (le.le_warn_percent * 100 / 65536)
        entry["flags"] = le_flags
        entry["diag_threshold_scaled"] = int(le.le_diag_threshold_scaled)
    else:
        return None
    
    entry["balance"] = entry["credit"] - entry["debit"]
    return entry

def GetLedgerEntryWithName(ledger_template, ledger, name):
    idx = GetLedgerEntryIndex(ledger_template, name)
    assert(idx != -1)
    return GetLedgerEntryWithTemplate(ledger_template, ledger, idx)

def FormatLedgerEntrySummary(entry, i, show_footprint_interval_max=False):
    """ internal function to format a ledger entry into a string
        params: entry - A python dictionary containing the ledger entry
        return: str - formatted output information of ledger entries
    """
    out_str = ''
    out_str += "{: >32s} {:<2d}:".format(entry["key"], i)
    out_str += "{: >15d} ".format(entry["balance"])

    if (show_footprint_interval_max):
        if "interval_max" in entry:
            out_str += "{:12d} ".format(entry["interval_max"])
        else:
            out_str += "           - "

    if "lifetime_max" in entry:
        out_str += "{:14d} ".format(entry["lifetime_max"])
    else:
        out_str += "             - "

    out_str += "{:12d} {:12d} ".format(entry["credit"], entry["debit"])
    if entry.get('limit', unsigned(ledger_limit_infinity)) != unsigned(ledger_limit_infinity):
        out_str += "{:12d} ".format(unsigned(entry["limit"]))
    else:
        out_str += "           - "

    if "refill_period" in entry:
        out_str += "{:15d} ".format(entry["refill_period"])
        if entry["refill_period"] != 0:
            out_str += "{:9d} ".format((entry["limit"] * 100) // entry["refill_period"])
        else:
            out_str += "XXXXX     - "
    else:
        out_str += "              - "
        out_str += "        - "

    if "warn_percent" in entry:
        out_str += "{:9d} ".format(entry["warn_percent"])
    else:
        out_str += "        - "

    if "limit" in entry:
        if entry["balance"] > entry["limit"]:
            out_str += "    X "
        else:
            out_str += "      "
    else:
        out_str += "      "

    out_str += "{:#8x}\n".format(entry["flags"])
    return out_str

def GetLedgerEntrySummary(ledger_template, ledger, i, show_footprint_interval_max=False):
    """ internal function to get internals of a ledger entry (*not* a ledger itself)
        params: ledger_template - value representing struct ledger_template_t for the task or thread
                ledger - value representing ledger pointer
        return: str - formatted output information of ledger entries
    """
    entry = GetLedgerEntryWithTemplate(ledger_template, ledger, i)
    return FormatLedgerEntrySummary(entry, i)


def GetThreadLedgers(thread_val):
    """ Internal function to get a summary of ledger entries for the given thread
        params: thread_val - value representing struct thread *
        return: thread - python dictionary containing threads's ledger entries. This can 
        be printed directly with FormatThreadLedgerSummmary or outputted as json.
    """
    thread = {}
    thread["address"] = unsigned(thread_val)
    ledgerp = thread_val.t_threadledger
    thread["entries"] = []
    if ledgerp:
        i = 0
        while i != ledgerp.l_template.lt_cnt:
            thread["entries"].append(GetLedgerEntryWithTemplate(kern.globals.thread_ledger_template,
                ledgerp, i))
            i = i + 1
    return thread

def FormatThreadLedgerSummary(thread):
    """ Internal function to print a thread's ledger entries
        params: thread - python dictionary containing thread's ledger entries
        return: str - formatted output information for ledger entries of the input thread
    """
    out_str = "   [{:#08x}]\n".format(thread["address"])
    entries = thread["entries"]
    for i, entry in enumerate(entries):
        out_str += FormatLedgerEntrySummary(entry, i)
    return out_str

def GetTaskLedgers(task_val):
    """ Internal function to get summary of ledger entries from the task and its threads
        params: task_val - value representing struct task *
        return: task - python dictionary containing tasks's ledger entries. This can 
        be printed directly with FormatTaskLedgerSummary or outputted as json.
    """
    task_ledgerp = task_val.ledger
    i = 0
    tasks = []
    task = {}
    task["address"] = unsigned(task_val)

    pval = GetProcFromTask(task_val)
    if pval is not None:
        task["name"] = GetProcName(pval)
        task["pid"] = int(GetProcPID(pval))

    task["entries"] = []
    while i != task_ledgerp.l_template.lt_cnt:
        task["entries"].append(GetLedgerEntryWithTemplate(kern.globals.task_ledger_template, task_ledgerp, i))
        i = i + 1

    # Now walk threads
    task["threads"] = []
    for thval in IterateQueue(task_val.threads, 'thread *', 'task_threads'):
        task["threads"].append(GetThreadLedgers(thval))

    return task

@header("{0: <15s} {1: >16s} {2: <2s} {3: >15s} {4: >14s} {5: >12s} {6: >12s} {7: >12s}   {8: <15s} {9: <8s} {10: <9s} {11: <6s} {12: >6s}".format(
            "task [thread]", "entry", "#", "balance", "lifetime_max", "credit",
            "debit", "limit", "refill period", "lim pct", "warn pct", "over?", "flags"))
def FormatTaskLedgerSummary(task, show_footprint_interval_max=False):
    """ Internal function to get summary of ledger entries from the task and its threads
        params: task_val - value representing struct task *
        return: str - formatted output information for ledger entries of the input task
    """
    out_str = ''
    out_str += "{: #08x} ".format(task["address"])
    if "name" in task:
        out_str += "{: <5s}:\n".format(task["name"])
    else:
        out_str += "Invalid process\n"

    for i, entry in enumerate(task["entries"]):
        out_str += FormatLedgerEntrySummary(entry, i, show_footprint_interval_max)

    for thread in task["threads"]:
        out_str += FormatThreadLedgerSummary(thread)
    return out_str


# Macro: showtaskledgers

@lldb_command('showtaskledgers', 'JF:I') 
def ShowTaskLedgers(cmd_args=None, cmd_options={}):
    """  Routine to print a summary  of ledger entries for the task and all of its threads
         or   : showtaskledgers [ -I ] [-J] [ -F ] <task>
         options:
            -I: show footprint interval max (DEV/DEBUG only)
            -F: specify task via name instead of address
            -J: output json
        -
    """
    print_json = False
    if "-F" in cmd_options:
        task_list = FindTasksByName(cmd_options["-F"])
        for tval in task_list:
            print(FormatTaskLedgerSummary.header)
            ledgers = GetTaskLedgers(tval)
            print(FormatTaskLedgerSummary(ledgers))
        return
    if "-J" in cmd_options:
        print_json = True
    
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed.")
    show_footprint_interval_max = False
    if "-I" in cmd_options:
        show_footprint_interval_max = True
    tval = addressof(kern.CreateValueFromAddress(cmd_args[0], 'task'))
    if not tval:
        raise ArgumentError("unknown arguments: %r" %cmd_args)
    ledgers = GetTaskLedgers(tval)
    if print_json:
        print(json.dumps(ledgers))
    else:
        if (show_footprint_interval_max):
            print("{0: <15s} {1: >16s} {2: <2s} {3: >15s} {4: >12s} {5: >14s} {6: >12s} {7: >12s} {8: >12s}   {9: <15s} {10: <8s} {11: <9s} {12: <6s} {13: >6s}".format(
            "task [thread]", "entry", "#", "balance", "intrvl_max", "lifetime_max", "credit",
            "debit", "limit", "refill period", "lim pct", "warn pct", "over?", "flags"))
        else:
            print(FormatTaskLedgerSummary.header)
        print(FormatTaskLedgerSummary(ledgers, show_footprint_interval_max))

# EndMacro: showtaskledgers

# Macro: showalltaskledgers

@lldb_command('showalltaskledgers', "J") 
def ShowAllTaskLedgers(cmd_args=None, cmd_options={}):
    """  Routine to print a summary  of ledger entries for all tasks and respective threads
         Usage: showalltaskledgers [-J]
            -J      : Output json
    """
    print_json = False
    if "-J" in cmd_options:
        print_json = True
    tasks = []
    for t in kern.tasks:
        task_val = unsigned(t)
        if not print_json:
            ShowTaskLedgers([task_val], cmd_options=cmd_options)
        else:
            tasks.append(GetTaskLedgers(t))
    if print_json:
        print(json.dumps(tasks))
    
# EndMacro: showalltaskledgers

# Macro: showprocuuidpolicytable

@lldb_type_summary(['proc_uuid_policy_entry'])
@header("{0: <36s} {1: <10s}".format("uuid", "flags"))
def GetProcUUIDPolicyEntrySummary(entry):
    """ Summarizes the important fields in proc_uuid_policy_entry structure.
        params: entry: value - value object representing an entry
        returns: str - summary of the entry
    """
    data = []
    for i in range(16):
        data.append(int(entry.uuid[i]))
    flags = unsigned(entry.flags)
    out_string = "{a[0]:02X}{a[1]:02X}{a[2]:02X}{a[3]:02X}-{a[4]:02X}{a[5]:02X}-{a[6]:02X}{a[7]:02X}-{a[8]:02X}{a[9]:02X}-{a[10]:02X}{a[11]:02X}{a[12]:02X}{a[13]:02X}{a[14]:02X}{a[15]:02X} 0x{b:0>8x}".format(a=data, b=flags)
    return out_string

@lldb_command('showprocuuidpolicytable')
def ShowProcUUIDPolicyTable(cmd_args=None):
    """ Routine to print the proc UUID policy table
        Usage: showprocuuidpolicytable
    """
    hashslots = unsigned(kern.globals.proc_uuid_policy_hash_mask)
    print("{0: <8s} ".format("slot") + GetProcUUIDPolicyEntrySummary.header)
    for i in range(0, hashslots+1):
        headp = addressof(kern.globals.proc_uuid_policy_hashtbl[i])
        entrynum = 0
        for entry in IterateListEntry(headp, 'entries'):
            print("{0: >2d}.{1: <5d} ".format(i, entrynum) + GetProcUUIDPolicyEntrySummary(entry))
            entrynum += 1


# EndMacro: showprocuuidpolicytable
def build_fields_string(obj: value, fields: list[list[str]]) -> str:
    result = ""
    for field_name, human_name in fields:
            if (trp_field_value := get_field(obj, field_name)) is not None:
                result += f"{human_name}: {str(trp_field_value)} "
    
    return result

@lldb_command('showalltaskpolicy') 
def ShowAllTaskPolicy(cmd_args=None):
    """  
         Routine to print a summary listing of all the tasks
         wq_state -> reports "number of workq threads", "number of scheduled workq threads", "number of pending work items"
         if "number of pending work items" seems stuck at non-zero, it may indicate that the workqueue mechanism is hung
         io_policy -> RAGE  - rapid aging of vnodes requested
                     NORM  - normal I/O explicitly requested (this is the default)
                     PASS  - passive I/O requested (i.e. I/Os do not affect throttling decisions)
                     THROT - throttled I/O requested (i.e. thread/task may be throttled after each I/O completes)
    """
    global kern
    print(GetTaskSummary.header + " " + GetProcSummary.header)
    for t in kern.tasks:
        pval = GetProcFromTask(t)
        print(GetTaskSummary(t) +" "+ GetProcSummary(pval))

        requested_strings = [
                ["trp_int_darwinbg",        "DBG-int"],
                ["trp_ext_darwinbg",        "DBG-ext"],
                ["trp_int_iotier",          "iotier-int"],
                ["trp_ext_iotier",          "iotier-ext"],
                ["trp_int_iopassive",       "passive-int"],
                ["trp_ext_iopassive",       "passive-ext"],
                ["trp_bg_iotier",           "bg-iotier"],
                ["trp_terminated",          "terminated"],
                # ["thrp_pidbind_bg",       "bg-pidbind"], # no longer part of task requested policy
                ["trp_apptype",           "apptype"],
                ["trp_boosted",           "boosted"],
                ["trp_role",              "role"],
                # ["trp_tal_enabled",       "tal-enabled"], # tal_enabled is unused/deprecated
                ["trp_base_latency_qos",  "latency-base"],
                ["trp_over_latency_qos",  "latency-override"],
                ["trp_base_through_qos",  "throughput-base"],
                ["trp_over_through_qos",  "throughput-override"]
                ]
        
        requested = build_fields_string(t.requested_policy, requested_strings)
        
        suppression_strings = [
                ["trp_sup_active",        "active"],
                ["trp_sup_lowpri_cpu",    "lowpri-cpu"],
                ["trp_sup_timer",         "timer-throttling"],
                ["trp_sup_disk",          "disk-throttling"],
                ["trp_sup_cpu_limit",     "cpu-limits"],
                ["trp_sup_suspend",       "suspend"],
                ["trp_sup_bg_sockets",    "bg-sockets"]
                ]
        suppression = build_fields_string(t.requested_policy, suppression_strings)

        effective_strings = [
                ["tep_darwinbg",        "background"],
                ["tep_lowpri_cpu",      "lowpri-cpu"],
                ["tep_io_tier",         "iotier"],
                ["tep_io_passive",      "passive"],
                ["tep_all_sockets_bg",  "bg-allsockets"],
                ["tep_new_sockets_bg",  "bg-newsockets"],
                ["tep_bg_iotier",       "bg-iotier"],
                ["tep_terminated",      "terminated"],
                # ["t_gpu_deny",      "gpu-deny"], # no longer exists
                ["tep_tal_engaged",   "tal-engaged"],
                # ["t_suspended",     "suspended"], # no longer exists
                ["tep_watchers_bg",   "bg-watchers"],
                ["tep_latency_qos",   "latency-qos"],
                ["tep_through_qos",   "throughput-qos"],
                ["tep_sup_active",    "suppression-active"],
                ["tep_role",          "role"]
                ]
        effective = build_fields_string(t.effective_policy, effective_strings)
                
        print("requested: " + requested)
        print("suppression: " + suppression)
        print("effective: " + effective)
        print("\n\n")


@lldb_command('showallsuspendedtasks', '')
def ShowSuspendedTasks(cmd_args=[], options={}):
    """ Show a list of suspended tasks with their process name summary.
    """
    print(GetTaskSummary.header + ' ' + GetProcSummary.header)
    for t in kern.tasks:
        if t.suspend_count > 0:
            print(GetTaskSummary(t) + ' ' + GetProcSummary(GetProcFromTask(t)))
    return True

# Macro: showallpte
@lldb_command('showallpte')
def ShowAllPte(cmd_args=None):
    """ Prints out the physical address of the pte for all tasks
    """
    head_taskp = addressof(kern.globals.tasks)
    taskp = Cast(head_taskp.next, 'task *')
    while taskp != head_taskp:
        out_str = "task = {:#x} pte = {:#x}\t".format(taskp, taskp.map.pmap.ttep)
        procp = GetProcFromTask(taskp)
        if procp is not None:
            out_str += "{:s}\n".format(GetProcName(procp))
        else:
            out_str += "\n"
        print(out_str)
        taskp = Cast(taskp.tasks.next, 'struct task *')

# EndMacro: showallpte

# Macro: showallrefcounts
@lldb_command('showallrefcounts')
@header("{0: <20s} {1: ^10s}".format("task", "ref_count"))
def ShowAllRefCounts(cmd_args=None):
    """ Prints the ref_count of all tasks
    """
    out_str = ''
    head_taskp = addressof(kern.globals.tasks)
    taskp = Cast(head_taskp.next, 'task *')
    print(ShowAllRefCounts.header)
    while taskp != head_taskp:
        out_str += "{: <#20x}".format(taskp)
        out_str += "{: ^10d}\n".format(taskp.ref_count.ref_count)
        taskp = Cast(taskp.tasks.next, 'task *')
    print(out_str)
# EndMacro: showallrefcounts

# Macro: showallrunnablethreads
@lldb_command('showallrunnablethreads', fancy=True)
def ShowAllRunnableThreads(cmd_args=None, cmd_options={}, O=None):
    """ Prints the sched usage information for all threads of each task
    """
    out_str = ''
    for taskp in kern.tasks:
        for actp in IterateQueue(taskp.threads, 'thread *', 'task_threads'):
            if int(actp.state & 0x4):
                ShowActStack([unsigned(actp)], O=O)

# EndMacro: showallrunnablethreads

# Macro: showallschedusage
@lldb_command('showallschedusage')
@header("{0:<20s} {1:^10s} {2:^10s} {3:^15s}".format("Thread", "Priority", "State", "sched_usage"))
def ShowAllSchedUsage(cmd_args=None):
    """ Prints the sched usage information for all threads of each task
    """
    out_str = ''
    for taskp in kern.tasks:
        ShowTask([str(unsigned(taskp))])
        print(ShowAllSchedUsage.header)
        for actp in IterateQueue(taskp.threads, 'thread *', 'task_threads'):
            out_str = "{: <#20x}".format(actp)
            out_str += "{: ^10s}".format(str(int(actp.sched_pri)))
            state = int(actp.state)
            state_str = ''
            mask = 0x1
            while mask <= LAST_THREAD_STATE:
                state_str += THREAD_STATE_CHARS[int(state & mask)]
                mask <<= 1
            out_str += "{: ^10s}".format(state_str)
            out_str += "{: >15d}".format(actp.sched_usage)
            print(out_str + "\n")
        print("\n\n")

# EndMacro: showallschedusage

#Macro: showprocfilessummary
@lldb_command('showprocfilessummary')
@header("{0: <20s} {1: <20s} {2: >10s}".format("Process", "Name", "Number of Open Files"))
def ShowProcFilesSummary(cmd_args=None):
    """ Display the summary of open file descriptors for all processes in task list
        Usage: showprocfilessummary
    """
    print(ShowProcFilesSummary.header)
    for proc in kern.procs:
        proc_filedesc = addressof(proc.p_fd)
        proc_ofiles = proc_filedesc.fd_ofiles
        proc_file_count = 0
        for fd in range(0, proc_filedesc.fd_afterlast):
            if unsigned(proc_ofiles[fd]) != 0:
                proc_file_count += 1
        print("{0: <#020x} {1: <32s} {2: >10d}".format(proc, GetProcName(proc), proc_file_count))

#EndMacro: showprocfilessummary

@lldb_command('workinguserstacks')
def WorkingUserStacks(cmd_args=None):
    """ Print out the user stack for each thread in a task, followed by the user libraries.
        Syntax: (lldb) workinguserstacks <task_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    print(GetTaskSummary.header + " " + GetProcSummary.header)
    pval = GetProcFromTask(task)
    print(GetTaskSummary(task) + " " + GetProcSummary(pval) + "\n \n")
    for thval in IterateQueue(task.threads, 'thread *', 'task_threads'):
        print("For thread 0x{0:x}".format(thval))
        try:
            ShowThreadUserStack([hex(thval)])
        except Exception as exc_err:
            print("Failed to show user stack for thread 0x{0:x}".format(thval))
            if config['debug']:
                raise exc_err
            else:
                print("Enable debugging ('(lldb) xnudebug debug') to see detailed trace.")
    WorkingUserLibraries([hex(task)])

@static_var("exec_load_path", 0)
@lldb_command("workingkuserlibraries")
def WorkingUserLibraries(cmd_args=None):
    """ Show binary images known by dyld in target task
        For a given user task, inspect the dyld shared library state and print information about all Mach-O images.
        Syntax: (lldb)workinguserlibraries <task_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    print("{0: <18s} {1: <12s} {2: <36s} {3: <50s}".format('address','type','uuid','path'))
    out_format = "0x{0:0>16x} {1: <12s} {2: <36s} {3: <50s}"
    task = kern.GetValueFromAddress(cmd_args[0], 'task_t')
    is_task_64 = int(task.t_flags) & 0x1
    dyld_all_image_infos_address = unsigned(task.all_image_info_addr)
    cur_data_offset = 0
    if dyld_all_image_infos_address == 0:
        print("No dyld shared library information available for task")
        return False
    vers_info_data = GetUserDataAsString(task, dyld_all_image_infos_address, 112)
    version = _ExtractDataFromString(vers_info_data, cur_data_offset, "uint32_t")
    cur_data_offset += 4
    if version > 12:
        print("Unknown dyld all_image_infos version number %d" % version)
    image_info_count = _ExtractDataFromString(vers_info_data, cur_data_offset, "uint32_t")
    WorkingUserLibraries.exec_load_path = 0
    if is_task_64:
        image_info_size = 24
        image_info_array_address = _ExtractDataFromString(vers_info_data, 8, "uint64_t")
        dyld_load_address = _ExtractDataFromString(vers_info_data, 8*4, "uint64_t")
        dyld_all_image_infos_address_from_struct = _ExtractDataFromString(vers_info_data, 8*13, "uint64_t")
    else:
        image_info_size = 12
        image_info_array_address = _ExtractDataFromString(vers_info_data, 4*2, "uint32_t")
        dyld_load_address = _ExtractDataFromString(vers_info_data, 4*5, "uint32_t")
        dyld_all_image_infos_address_from_struct = _ExtractDataFromString(vers_info_data, 4*14, "uint32_t")
    # Account for ASLR slide before dyld can fix the structure
    dyld_load_address = dyld_load_address + (dyld_all_image_infos_address - dyld_all_image_infos_address_from_struct)

    i = 0
    while i < image_info_count:
        image_info_address = image_info_array_address + i * image_info_size
        img_data = GetUserDataAsString(task, image_info_address, image_info_size)
        if is_task_64:
            image_info_addr = _ExtractDataFromString(img_data, 0, "uint64_t")
            image_info_path = _ExtractDataFromString(img_data, 8, "uint64_t")
        else:
            image_info_addr = _ExtractDataFromString(img_data, 0, "uint32_t")
            image_info_path = _ExtractDataFromString(img_data, 4, "uint32_t")
        PrintImageInfo(task, image_info_addr, image_info_path)
        i += 1

    # load_path might get set when the main executable is processed.
    if WorkingUserLibraries.exec_load_path != 0:
        PrintImageInfo(task, dyld_load_address, WorkingUserLibraries.exec_load_path)
    return

# Macro: showstackaftertask

@lldb_command('showstackaftertask', 'F:', fancy=True)
def Showstackaftertask(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print the thread stacks for all tasks succeeding a given task
        Usage: showstackaftertask <0xaddress of task>
           or: showstackaftertask  -F <taskname>
    """
    if "-F" in cmd_options:
        # Find the task pointer corresponding to its task name
        find_task_str = cmd_options["-F"]
        task_list = FindTasksByName(find_task_str)

        # Iterate through the list of tasks and print all task stacks thereafter
        for tval in task_list:
            ListTaskStacks(tval, O=O)
        return

    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Insufficient arguments")
    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        raise ArgumentError("unknown arguments: {:s}".format(str(cmd_args)))
    else:
        ListTaskStacks(tval, O=O)

    ShowZombStacks(O=O)

# EndMacro: showstackaftertask

def ListTaskStacks(task, O=None):
    """ Search for a given task and print the list of all task stacks thereafter.
    """
    # Initialize local variable task_flag to mark when a given task is found.
    task_flag=0

    for t in kern.tasks:
        if (task_flag == 1):
            ShowTaskStacks(t, O=O)
            print("\n")
        if (t == task):
            task_flag = 1

# Macro: showstackafterthread
@lldb_command('showstackafterthread', fancy=True)
def Showstackafterthread(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print the stacks of all threads succeeding a given thread.
        Usage: Showstackafterthread <0xaddress of thread>
    """
    # local variable thread_flag is used to mark when a given thread is found.
    thread_flag=0
    if cmd_args:
       threadval = kern.GetValueFromAddress(cmd_args[0], 'thread *')
    else:
        raise ArgumentError("No arguments passed")
    # Iterate through list of all tasks to look up a given thread
    for t in kern.tasks:
        if(thread_flag==1):
            pval = GetProcFromTask(t)
            print(GetTaskSummary.header + " "+ GetProcSummary.header)
            print(GetTaskSummary(t) +     " "+ GetProcSummary(pval))
            print("\n")
         # Look up for a given thread from the the list of threads of a given task
        for thval in IterateQueue(t.threads, 'thread *', 'task_threads'):
            if thread_flag == 1:
                print("\n")
                with O.table(GetThreadSummary.header, indent=True):
                    print(GetThreadSummary(active_thread, O=O))
                print(GetThreadBackTrace(thval, prefix="\t")+"\n")
                print("\n")

            if thval == threadval:
                pval = GetProcFromTask(t)
                process_name = "{:s}".format(GetProcName(pval))
                print("\n\n")
                print(" *** Continuing to dump the thread stacks from the process *** :" + " " + process_name)
                print("\n\n")
                thread_flag = 1
        print('\n')
    return

