"""
Miscellaneous (Intel) platform-specific commands.
"""
from core import caching
from xnu import *
import xnudefines

from scheduler import *
from xnu import GetTaskTerminatedUserSysTime

@lldb_command('showmcastate')
def showMCAstate(cmd_args=None):
    """
    Print machine-check register state after MC exception.
    """
    if kern.arch != 'x86_64':
        print("Not available for current architecture.")
        return

    present = ["not present", "present"]
    print('MCA {:s}, control MSR {:s}, threshold status {:s}'.format(
    present[int(kern.globals.mca_MCA_present)],
    present[int(kern.globals.mca_control_MSR_present)],
    present[int(kern.globals.mca_threshold_status_present)]))
    print('{:d} error banks, family code {:#0x}, machine-check dump state: {:d}'.format(
        kern.globals.mca_error_bank_count,
        kern.globals.mca_dump_state,
        kern.globals.mca_family))
    cpu = 0
    while kern.globals.cpu_data_ptr[cpu]:
        cd = kern.globals.cpu_data_ptr[cpu]
        mc = cd.cpu_mca_state
        if mc:
            print('CPU {:d}: mca_mcg_ctl: {:#018x} mca_mcg_status {:#018x}'.format(cpu, mc.mca_mcg_ctl, mc.mca_mcg_status.u64))
            hdr = '{:<4s} {:<18s} {:<18s} {:<18s} {:<18s}'
            val = '{:>3d}: {:#018x} {:#018x} {:#018x} {:#018x}'
            print(hdr.format('bank',
                    'mca_mci_ctl',
                    'mca_mci_status',
                    'mca_mci_addr',
                    'mca_mci_misc'))
            for i in range(int(kern.globals.mca_error_bank_count)):
                bank = mc.mca_error_bank[i]
                print(val.format(i,
                    bank.mca_mci_ctl,
                    bank.mca_mci_status.u64,
                    bank.mca_mci_addr,     
                    bank.mca_mci_misc))     
        print('register state:')
        reg = cd.cpu_desc_index.cdi_ktss.ist1 - sizeof('x86_saved_state_t')
        print(lldb_run_command('p/x *(x86_saved_state_t *) ' + hex(reg)))
        cpu = cpu + 1

def dumpTimerList(mpqueue, processor=None):
    """
    Utility function to dump the timer entries in list (anchor).
    anchor is a struct mpqueue_head.
    """

    if mpqueue.count == 0:
        print('(empty)')
        return

    thdr = ' {:<24s}{:^17s}{:^18s} {:^18s} {:^18s} {:^18s} {:^18s} {:9s} {:^18s} count: {:d} '
    tval = ' {:#018x}{:s} {:18d} {:18d} {:18.06f} {:18.06f} {:18.06f} {:18.06f} {:>9s}  ({:#018x})({:#018x}, {:#018x}) ({:s}) {:s}'

    print(thdr.format('Entry', 'Soft Deadline', 'Deadline', 'Soft To Go', 'Hard To Go', 'Duration', 'Leeway', 'Flags', '(*func)(param0, param1)', mpqueue.count))

    recent_timestamp = GetRecentTimestamp()

    for timer_call in ParanoidIterateLinkageChain(mpqueue.head, 'struct timer_call *', 'tc_qlink'):

        func_name = kern.Symbolicate(timer_call.tc_func)

        extra_string = ""

        strip_func = kern.StripKernelPAC(unsigned(timer_call.tc_func))

        func_syms = kern.SymbolicateFromAddress(strip_func)
        # returns an array of SBSymbol

        if func_syms and func_syms[0] :
            func_sym = func_syms[0]
            func_name = func_sym.GetName()
            try :

                if "thread_call_delayed_timer" in func_name :
                    group = Cast(timer_call.tc_param0, 'struct thread_call_group *')
                    flavor = Cast(timer_call.tc_param1, 'thread_call_flavor_t')

                    # There's got to be a better way to stringify the enum
                    flavorname = str(flavor).partition(" = ")[2]
                    extra_string += "{:s} {:s}".format(group.tcg_name, flavorname)

                if "thread_timer_expire" in func_name :
                    thread = Cast(timer_call.tc_param0, 'thread_t')

                    tid = thread.thread_id
                    name = GetThreadName(thread)
                    pid = GetProcPIDForTask(thread.t_tro.tro_task)
                    procname = GetProcNameForTask(thread.t_tro.tro_task)

                    otherprocessor = ""
                    if processor :
                        if thread.last_processor != processor:
                            otherprocessor = " (Not same processor - was on {:d})".format(thread.last_processor.cpu_id)

                    extra_string += "thread: 0x{:x} {:s} task:{:s}[{:d}]{:s}".format(
                            tid, name, procname, pid, otherprocessor)
            except:
                print("exception generating extra_string for call: {:#018x}".format(timer_call))
                if dumpTimerList.enable_debug :
                    raise

        timer_fire = timer_call.tc_pqlink.deadline - recent_timestamp
        timer_fire_s = kern.GetNanotimeFromAbstime(timer_fire) / 1000000000.0

        soft_timer_fire = timer_call.tc_soft_deadline - recent_timestamp
        soft_timer_fire_s = kern.GetNanotimeFromAbstime(soft_timer_fire) / 1000000000.0

        leeway = timer_call.tc_pqlink.deadline - timer_call.tc_soft_deadline
        leeway_s = kern.GetNanotimeFromAbstime(leeway) / 1000000000.0

        tc_ttd_s = kern.GetNanotimeFromAbstime(timer_call.tc_ttd) / 1000000000.0

        flags = int(timer_call.tc_flags)
        timer_call_flags = {0x0:'', 0x1:'C', 0x2:'B', 0x4:'X', 0x8:'X', 0x10:'U', 0x20:'E',
                0x40:'L', 0x80:'R'}

        flags_str = ''
        mask = 0x1
        while mask <= 0x80 :
            flags_str += timer_call_flags[int(flags & mask)]
            mask = mask << 1

        colon = ":"

        if addressof(timer_call.tc_pqlink) == mpqueue.mpq_pqhead.pq_root :
            colon = "*"

        print(tval.format(timer_call, colon,
            timer_call.tc_soft_deadline,
            timer_call.tc_pqlink.deadline,
            soft_timer_fire_s,
            timer_fire_s,
            tc_ttd_s,
            leeway_s,
            flags_str,
            timer_call.tc_func,
            timer_call.tc_param0,
            timer_call.tc_param1,
            func_name, extra_string))

dumpTimerList.enable_debug = False

def GetCpuDataForCpuID(cpu_id):
    """
    Find struct cpu_data for a CPU
    ARM is complicated
    """
    if kern.arch == 'x86_64':
        cpu_data = kern.globals.cpu_data_ptr[cpu_id]
        return cpu_data
    elif kern.arch.startswith('arm'):
        data_entries_addr = kern.GetLoadAddressForSymbol('CpuDataEntries')
        data_entries = kern.GetValueFromAddress(data_entries_addr, 'cpu_data_entry_t *')
        data_entry = data_entries[cpu_id];
        cpu_data_addr = data_entry.cpu_data_vaddr
        return Cast(cpu_data_addr, 'cpu_data_t*')

@lldb_command('longtermtimers')
def longtermTimers(cmd_args=None):
    """
    Print details of long-term timers and stats.
    """

    lt = kern.globals.timer_longterm
    ltt = lt.threshold
    EndofAllTime = signed(-1)
    if signed(ltt.interval) == EndofAllTime:
        print("Longterm timers disabled")
        return

    if lt.escalates > 0:
        ratio = lt.enqueues // lt.escalates
    else:
        ratio = lt.enqueues
    print('Longterm timer object: {:#018x}'.format(addressof(lt)))
    print(' queue count         : {:d}'    .format(lt.queue.count))
    print(' number of enqueues  : {:d}'    .format(lt.enqueues))
    print(' number of dequeues  : {:d}'    .format(lt.dequeues))
    print(' number of escalates : {:d}'    .format(lt.escalates))
    print(' enqueues/escalates  : {:d}'    .format(ratio))
    print(' threshold.interval  : {:d}'    .format(ltt.interval))
    print(' threshold.margin    : {:d}'    .format(ltt.margin))
    print(' scan_time           : {:#018x} ({:d})'.format(lt.scan_time, lt.scan_time))
    if signed(ltt.preempted) == EndofAllTime:
        print(' threshold.preempted : None')
    else:
        print(' threshold.preempted : {:#018x} ({:d})'.format(ltt.preempted, ltt.preempted))
    if signed(ltt.deadline) == EndofAllTime:
        print(' threshold.deadline  : None')
    else:
        print(' threshold.deadline  : {:#018x} ({:d})'.format(ltt.deadline, ltt.deadline))
        print(' threshold.call      : {:#018x}'.format(ltt.call))
        print(' actual deadline set : {:#018x} ({:d})'.format(ltt.deadline_set, ltt.deadline_set))
    print(' threshold.scans     : {:d}'    .format(ltt.scans))
    print(' threshold.preempts  : {:d}'    .format(ltt.preempts))
    print(' threshold.latency   : {:d}'    .format(ltt.latency))
    print('               - min : {:d}'    .format(ltt.latency_min))
    print('               - max : {:d}'    .format(ltt.latency_max))
    dumpTimerList(lt.queue)


@lldb_command('processortimers')
def processorTimers(cmd_args=None):
    """
    Print details of processor timers, noting anything suspicious
    Also include long-term timer details

        Callout flags:

        C - Critical
        B - Background
        U - User timer
        E - Explicit Leeway
        L - Local
        R - Rate-limited - (App Nap)
    """

    recent_timestamp = GetRecentTimestamp()

    hdr = '{:15s}{:<18s} {:<18s} {:<18s} {:<18s} {:<18s} {:<18s} {:<18s} Recent Timestamp: {:d}'
    print(hdr.format('Processor #', 'Processor pointer', 'Last dispatch', 'Soft deadline', 'Soft To Go', 'Hard deadline', 'Hard To Go', 'Current Leeway', recent_timestamp))
    print("=" * 82)
    p = kern.globals.processor_list
    EndOfAllTime = signed(-1)
    while p:
        cpu = p.cpu_id
        cpu_data = GetCpuDataForCpuID(cpu)
        rt_timer = cpu_data.rtclock_timer
        diff = signed(rt_timer.deadline) - signed(recent_timestamp)
        diff_s = kern.GetNanotimeFromAbstime(diff) / 1000000000.0
        valid_deadline = signed(rt_timer.deadline) != EndOfAllTime
        soft_deadline = rt_timer.queue.earliest_soft_deadline
        soft_diff = signed(soft_deadline) - signed(recent_timestamp)
        soft_diff_s = kern.GetNanotimeFromAbstime(soft_diff) / 1000000000.0
        valid_soft_deadline = signed(soft_deadline) != EndOfAllTime
        leeway_s = kern.GetNanotimeFromAbstime(rt_timer.deadline - soft_deadline) / 1000000000.0
        tmr = 'Processor {:<3d}: {:#018x} {:<18d} {:<18s} {:<18s} {:<18s} {:<18s} {:<18s} {:s} {:s}'
        print(tmr.format(cpu,
            p,
            p.last_dispatch,
            "{:d}".format(soft_deadline) if valid_soft_deadline else "None",
            "{:<16.06f}".format(soft_diff_s) if valid_soft_deadline else "N/A",
            "{:d}".format(rt_timer.deadline) if valid_deadline else "None",
            "{:<16.06f}".format(diff_s) if valid_deadline else "N/A",
            "{:<16.06f}".format(leeway_s) if valid_soft_deadline and valid_deadline else "N/A",
            ['(PAST SOFT DEADLINE)', '(soft deadline ok)'][int(soft_diff > 0)] if valid_soft_deadline else "",
            ['(PAST DEADLINE)', '(deadline ok)'][int(diff > 0)] if valid_deadline else ""))
        if valid_deadline:
            if kern.arch == 'x86_64':
                print('Next deadline set at: {:#018x}. Timer call list:'.format(rt_timer.when_set))
            dumpTimerList(rt_timer.queue, p)
        p = p.processor_list
    print("-" * 82)
    longtermTimers()
    print("Running timers:")
    ShowRunningTimers()

@header("{:<6s}  {:^18s} {:^18s}".format("cpu_id", "Processor", "cpu_data") )
@lldb_command('showcpudata')
def ShowCPUData(cmd_args=[]):
    """ Prints the CPU Data struct of each processor
        Passing a CPU ID prints the CPU Data of just that CPU
        Usage: (lldb) showcpudata [cpu id]
    """

    format_string = "{:>#6d}: {: <#018x} {: <#018x}"

    find_cpu_id = None

    if cmd_args:
        find_cpu_id = ArgumentStringToInt(cmd_args[0])

    print (ShowCPUData.header)

    processors = [p for p in IterateLinkedList(kern.globals.processor_list, 'processor_list')]

    processors.sort(key=lambda p: p.cpu_id)

    for processor in processors:
        cpu_id = int(processor.cpu_id)

        if find_cpu_id and cpu_id != find_cpu_id:
            continue

        cpu_data = GetCpuDataForCpuID(cpu_id)

        print (format_string.format(cpu_id, processor, cpu_data))

@lldb_command('showtimerwakeupstats')
def showTimerWakeupStats(cmd_args=None):
    """
    Displays interrupt and platform idle wakeup frequencies
    associated with each thread, timer time-to-deadline frequencies, and
    CPU time with user/system break down where applicable, with thread tags.
    """
    for task in kern.tasks:
        proc = GetProcFromTask(task)
        print(dereference(task))
        (user_time, sys_time) = GetTaskTerminatedUserSysTime(task)
        print('{:d}({:s}), terminated thread timer wakeups: {:d} {:d} 2ms: {:d} 5ms: {:d} UT: {:d} ST: {:d}'.format(
            GetProcPID(proc),
            GetProcName(proc),
# Commented-out references below to be addressed by rdar://13009660.
            0, #task.task_interrupt_wakeups,
            0, #task.task_platform_idle_wakeups,
            task.task_timer_wakeups_bin_1,
            task.task_timer_wakeups_bin_2,
            user_time, sys_time))
        tot_wakes = 0 #task.task_interrupt_wakeups
        tot_platform_wakes = 0 #task.task_platform_idle_wakeups
        for thread in IterateQueue(task.threads, 'thread_t', 'task_threads'):
##        if thread.thread_interrupt_wakeups == 0:
##              continue
            (user_time, sys_time) = GetThreadUserSysTime(thread)
            print('\tThread ID 0x{:x}, Tag 0x{:x}, timer wakeups: {:d} {:d} {:d} {:d} <2ms: {:d}, <5ms: {:d} UT: {:d} ST: {:d}'.format(
                thread.thread_id,
                thread.thread_tag,
                0, #thread.thread_interrupt_wakeups,
                0, #thread.thread_platform_idle_wakeups,
                0, #thread.thread_callout_interrupt_wakeups,
                0, #thread.thread_callout_platform_idle_wakeups,
                0,0,0,0,
                thread.thread_timer_wakeups_bin_1,
                thread.thread_timer_wakeups_bin_2,
                user_time, sys_time))
            tot_wakes += 0 #thread.thread_interrupt_wakeups
            tot_platform_wakes += 0 #thread.thread_platform_idle_wakeups
        print('Task total wakeups: {:d} {:d}'.format(
            tot_wakes, tot_platform_wakes))

@lldb_command('showrunningtimers')
def ShowRunningTimers(cmd_args=None):
    """
    Print the state of all running timers.

    Usage: showrunningtimers
    """
    processor_array = kern.globals.processor_array

    recent_timestamp = GetRecentTimestamp()

    hdr = '{:4s} {:^10s} {:^18s} {:^18s} {:^18s} {:^18s}'
    print(hdr.format('CPU', 'State', 'Quantum', 'To Go', 'kperf', 'To Go', 'Hard To Go'))

    cpu = '{:3d}: {:^10s} {:18d} {:16.06f} {:18d} {:16.06f}'

    i = 0
    while processor_array[i] != 0:
        processor = processor_array[i]

        statestr = 'runnning' if processor.running_timers_active else 'idle'

        quantum = unsigned(processor.running_timers[0].tc_pqlink.deadline)
        quantumdiff = signed(quantum) - signed(recent_timestamp)
        quantumdiff_s = kern.GetNanotimeFromAbstime(quantumdiff) / 1000000000.0

        kperf = unsigned(processor.running_timers[1].tc_pqlink.deadline)
        kperfdiff = signed(kperf) - signed(recent_timestamp)
        kperfdiff_s = kern.GetNanotimeFromAbstime(kperfdiff) / 1000000000.0

        print (cpu.format(i, statestr, quantum, quantumdiff_s, kperf, kperfdiff_s))
        i += 1

def DoReadMsr64(msr_address, lcpu):
    """ Read a 64-bit MSR from the specified CPU
        Params:
            msr_address: int - MSR index to read from
            lcpu: int - CPU identifier
        Returns:
            64-bit value read from the MSR
    """
    result = 0xbad10ad

    if "kdp" != GetConnectionProtocol():
        print("Target is not connected over kdp. Cannot read MSR.")
        return result

    input_address = unsigned(addressof(kern.globals.manual_pkt.input))
    len_address = unsigned(addressof(kern.globals.manual_pkt.len))
    data_address = unsigned(addressof(kern.globals.manual_pkt.data))
    if not WriteInt32ToMemoryAddress(0, input_address):
        print("DoReadMsr64() failed to write 0 to input_address")
        return result
    
    kdp_pkt_size = GetType('kdp_readmsr64_req_t').GetByteSize()
    if not WriteInt32ToMemoryAddress(kdp_pkt_size, len_address):
        print("DoReadMsr64() failed to write kdp_pkt_size")
        return result
    
    kgm_pkt = kern.GetValueFromAddress(data_address, 'kdp_readmsr64_req_t *')
    header_value = GetKDPPacketHeaderInt(
        request=GetEnumValue('kdp_req_t::KDP_READMSR64'),
        length=kdp_pkt_size)

    if not WriteInt64ToMemoryAddress(header_value, int(addressof(kgm_pkt.hdr))):
        print("DoReadMsr64() failed to write header_value")
        return result
    if not WriteInt32ToMemoryAddress(msr_address, int(addressof(kgm_pkt.address))):
        print("DoReadMsr64() failed to write msr_address")
        return result
    if not WriteInt16ToMemoryAddress(lcpu, int(addressof(kgm_pkt.lcpu))):
        print("DoReadMsr64() failed to write lcpu")
        return result
    if not WriteInt32ToMemoryAddress(1, input_address):
        print("DoReadMsr64() failed to write to input_address")
        return result

    result_pkt = Cast(addressof(kern.globals.manual_pkt.data),
        'kdp_readmsr64_reply_t *')
    if (result_pkt.error == 0):
        result = dereference(Cast(addressof(result_pkt.data), 'uint64_t *'))
    else:
        print("DoReadMsr64() result_pkt.error != 0")
    return result

def DoWriteMsr64(msr_address, lcpu, data):
    """ Write a 64-bit MSR
        Params: 
            msr_address: int - MSR index to write to
            lcpu: int - CPU identifier
            data: int - value to write
        Returns:
            True upon success, False if error
    """
    if "kdp" != GetConnectionProtocol():
        print("Target is not connected over kdp. Cannot write MSR.")
        return False

    input_address = unsigned(addressof(kern.globals.manual_pkt.input))
    len_address = unsigned(addressof(kern.globals.manual_pkt.len))
    data_address = unsigned(addressof(kern.globals.manual_pkt.data))
    if not WriteInt32ToMemoryAddress(0, input_address):
        print("DoWriteMsr64() failed to write 0 to input_address")
        return False
    
    kdp_pkt_size = GetType('kdp_writemsr64_req_t').GetByteSize()
    if not WriteInt32ToMemoryAddress(kdp_pkt_size, len_address):
        print("DoWriteMsr64() failed to kdp_pkt_size")
        return False
    
    kgm_pkt = kern.GetValueFromAddress(data_address, 'kdp_writemsr64_req_t *')
    header_value = GetKDPPacketHeaderInt(
        request=GetEnumValue('kdp_req_t::KDP_WRITEMSR64'),
        length=kdp_pkt_size)
    
    if not WriteInt64ToMemoryAddress(header_value, int(addressof(kgm_pkt.hdr))):
        print("DoWriteMsr64() failed to write header_value")
        return False
    if not WriteInt32ToMemoryAddress(msr_address, int(addressof(kgm_pkt.address))):
        print("DoWriteMsr64() failed to write msr_address")
        return False
    if not WriteInt16ToMemoryAddress(lcpu, int(addressof(kgm_pkt.lcpu))):
        print("DoWriteMsr64() failed to write lcpu")
        return False
    if not WriteInt64ToMemoryAddress(data, int(addressof(kgm_pkt.data))):
        print("DoWriteMsr64() failed to write data")
        return False
    if not WriteInt32ToMemoryAddress(1, input_address):
        print("DoWriteMsr64() failed to write to input_address")
        return False

    result_pkt = Cast(addressof(kern.globals.manual_pkt.data),
        'kdp_writemsr64_reply_t *')
    if not result_pkt.error == 0:
        print("DoWriteMsr64() error received in reply packet")
        return False
    
    return True

@lldb_command('readmsr64')
def ReadMsr64(cmd_args=None):
    """ Read the specified MSR. The CPU can be optionally specified
        Syntax: readmsr64 <msr> [lcpu]
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    
    msr_address = ArgumentStringToInt(cmd_args[0])
    if len(cmd_args) > 1:
        lcpu = ArgumentStringToInt(cmd_args[1])
    else:
        lcpu = int(xnudefines.lcpu_self)

    msr_value = DoReadMsr64(msr_address, lcpu)
    print("MSR[{:x}]: {:#016x}".format(msr_address, msr_value))

@lldb_command('writemsr64')
def WriteMsr64(cmd_args=None):
    """ Write the specified MSR. The CPU can be optionally specified
        Syntax: writemsr64 <msr> <value> [lcpu]
    """
    if cmd_args is None or len(cmd_args) < 2:
        raise ArgumentError()

    msr_address = ArgumentStringToInt(cmd_args[0])
    write_val = ArgumentStringToInt(cmd_args[1])
    if len(cmd_args) > 2:
        lcpu = ArgumentStringToInt(cmd_args[2])
    else:
        lcpu = xnudefines.lcpu_self

    if not DoWriteMsr64(msr_address, lcpu, write_val):
        print("writemsr64 FAILED")


@caching.cache_statically
def GetTimebaseInfo(target=None):
    if kern.arch == 'x86_64':
        return 1, 1

    rtclockdata_addr = kern.GetLoadAddressForSymbol('RTClockData')
    rtc = kern.GetValueFromAddress(
        rtclockdata_addr, 'struct _rtclock_data_ *')
    tb = rtc.rtc_timebase_const
    return int(tb.numer), int(tb.denom)


def PrintIteratedElem(i, elem, elem_type, do_summary, summary, regex):
    try:
        if do_summary and summary:
            s = summary(elem)
            if regex:
                if regex.match(s):
                    print("[{:d}] {:s}".format(i, s))
            else:
                print("[{:d}] {:s}".format(i, s))
        else:
            if regex:
                if regex.match(str(elem)):
                    print("[{:4d}] ({:s}){:#x}".format(i, elem_type, unsigned(elem)))
            else:
                print("[{:4d}] ({:s}){:#x}".format(i, elem_type, unsigned(elem)))
    except:
        print("Exception while looking at elem {:#x}".format(unsigned(elem)))
        return

@lldb_command('q_iterate', "LQSG:")
def QIterate(cmd_args=None, cmd_options={}):
    """ Iterate over a LinkageChain or Queue (osfmk/kern/queue.h method 1 or 2 respectively)
        This is equivalent to the qe_foreach_element() macro
        usage:
            iterate [options] {queue_head_ptr} {element_type} {field_name}
        option:
            -L    iterate over a linkage chain (method 1) [default]
            -Q    iterate over a queue         (method 2)

            -S    auto-summarize known types
            -G    regex to filter the output
        e.g.
            iterate_linkage `&coalitions_q` 'coalition *' coalitions
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("usage: iterate_linkage {queue_head_ptr} {element_type} {field_name}")

    qhead = kern.GetValueFromAddress(cmd_args[0], 'struct queue_entry *')
    if not qhead:
        raise ArgumentError("Unknown queue_head pointer: %r" % cmd_args)
    elem_type = cmd_args[1]
    field_name = cmd_args[2]
    if not elem_type or not field_name:
        raise ArgumentError("usage: iterate_linkage {queue_head_ptr} {element_type} {field_name}")

    do_queue_iterate = False
    do_linkage_iterate = True
    if "-Q" in cmd_options:
        do_queue_iterate = True
        do_linkage_iterate = False
    if "-L" in cmd_options:
        do_queue_iterate = False
        do_linkage_iterate = True

    do_summary = False
    if "-S" in cmd_options:
        do_summary = True
    regex = None
    if "-G" in cmd_options:
        regex = re.compile(".*{:s}.*".format(cmd_options["-G"]))
        print("Looking for: {:s}".format(regex.pattern))

    global lldb_summary_definitions
    summary = None
    if elem_type in lldb_summary_definitions:
        summary = lldb_summary_definitions[elem_type]
        if do_summary:
            print(summary.header)

    try:
        i = 0
        if do_linkage_iterate:
            for elem in IterateLinkageChain(qhead, elem_type, field_name):
                PrintIteratedElem(i, elem, elem_type, do_summary, summary, regex)
                i = i + 1
        elif do_queue_iterate:
            for elem in IterateQueue(qhead, elem_type, field_name):
                PrintIteratedElem(i, elem, elem_type, do_summary, summary, regex)
                i = i + 1
    except:
        print("Exception while looking at queue_head: {:#x}".format(unsigned(qhead)))

@lldb_command('lbrbt')
def LBRBacktrace(cmd_args=None):
    """
        Prints symbolicated last branch records captured on Intel systems
        from a core file. Will not work on a live system.
        usage:
            lbrbt
        options:
            None
    """
    if IsDebuggingCore() or kern.arch.startswith('arm'):
        print("Command is only supported on live Intel systems")
        return

    DecoratedLBRStack = SymbolicateLBR()
    if (DecoratedLBRStack):
        print(DecoratedLBRStack)

def SymbolicateLBR():
    lbr_size_offset = 5
    cpu_num_offset = 4
    LBRMagic = 0x5352424C
    
    try:
        phys_carveout_addr = kern.GetLoadAddressForSymbol("phys_carveout")
    except LookupError:
        print("Last Branch Recoreds not present in this core file")
        return None
    try:
        phys_carveout_md_addr = kern.GetLoadAddressForSymbol("panic_lbr_header")
    except LookupError:
        print("Last Branch Recoreds not present in this core file")
        return None

    metadata_ptr = kern.GetValueFromAddress(phys_carveout_md_addr, "uint64_t *")
    metadata = kern.GetValueFromAddress(unsigned(metadata_ptr[0]), "uint8_t *")
    carveout_ptr = kern.GetValueFromAddress(phys_carveout_addr, "uint64_t *")

    metadata_hdr = kern.GetValueFromAddress(unsigned(metadata_ptr[0]), "uint32_t *")
    if not (unsigned(metadata_hdr[0]) == LBRMagic):
        print("'LBRS' not found at beginning of phys_carveout section, cannot proceed.")
        return None

    lbr_records = unsigned(carveout_ptr[0])

    num_lbrs = int(metadata[lbr_size_offset])

    header_line = "".join("{:49s} -> {:s}\n".format("From", "To"))
    ncpus = int(metadata[cpu_num_offset])

    output_lines = [] 

    target = LazyTarget.GetTarget()

    for cpu in range(ncpus):
        start_addr_from = lbr_records + num_lbrs * 8 * cpu
        start_addr_to = start_addr_from + num_lbrs * 8 * ncpus
        from_lbr = kern.GetValueFromAddress(start_addr_from, "uint64_t *")
        to_lbr = kern.GetValueFromAddress(start_addr_to, "uint64_t *")
        for i in range(num_lbrs):
            if (from_lbr[i] == 0x0 or to_lbr[i] == 0x0):
                break
            ## Replace newline with space to include inlined functions
            ## in a trade off for longer output lines. 
            fprint = str(target.ResolveLoadAddress(int(from_lbr[i]))).replace('\n', ' ')
            tprint = str(target.ResolveLoadAddress(int(to_lbr[i]))).replace('\n', ' ')
            output_lines.append(''.join("({:x}) {:30s} -> ({:x}) {:30s}\n".format(from_lbr[i], fprint, to_lbr[i], tprint)))

    return header_line + ''.join(output_lines)
