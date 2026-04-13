from __future__ import absolute_import, division, print_function

from xnu import kern, lldb_command, ArgumentError, validate_args, unsigned, cast, addressof, GetEnumValue, GetEnumName, GetCpuDataForCpuID

cyclic_header = '{:>18s} {:>4s} {:>20s} {:>30s} {:>5s} {:>5s}'.format(
        'cyclic', 'slot', 'period', 'func', 'state', 'calls')
call_header = '{:>18s} {:>8s} {:>5s}'.format('call', 'deadline', 'state')

@lldb_command('cpc', 'A', fancy=True)
def CPC(cmd_args=None, cmd_options={}, O=None):  # noqa: E741
    """ Inspect the CPU Performance Counter subsystem.

        cpc processor [-A] [<processor_t-or-cpu-id>] [...]
        cpc set <cpc-set-addr> [...]
        cpc cyclic <cpc-cyclic-addr> [...]

        Options:
            -A : show all processors

        Diagnostic macros:
            cpc triage
    """
    if not cmd_args:
        raise ArgumentError('subcommand required')

    if cmd_args[0] == 'processor':
        validate_args(cmd_options, ['A'])
        CPCProcessor(cmd_args[1:], cmd_options=cmd_options, O=O)
    elif cmd_args[0] == 'set':
        if len(cmd_args) < 2:
            raise ArgumentError('cpc set expected a cpc_set_t address')
        for set_addr_str in cmd_args[1:]:
            set_addr = kern.GetValueFromAddress(set_addr_str, 'cpc_set_t')
            print('cpc_set_t 0x{:x}:'.format(set_addr))
            PrintCPCSet(set_addr, print_cyclics=True, O=O)
    elif cmd_args[0] == 'cyclic':
        if len(cmd_args) < 2:
            raise ArgumentError('cpc cyclic expected a cpc_cyclic_t address')
        with O.table(cyclic_header):
            for cyclic_addr_str in cmd_args[1:]:
                cyclic_addr = kern.GetValueFromAddress(cyclic_addr_str, 'cpc_cyclic_t')
                PrintCPCCyclic(cyclic_addr, O=O)
    elif cmd_args[0] == 'kpc':
        validate_args(cmd_options, [])
        PrintKPCState(O=O)
    elif cmd_args[0] == 'triage':
        validate_args(cmd_options, [])
        CPCTriage(cmd_options=cmd_options, O=O)
    else:
        raise ArgumentError('{}: invalid subcommand'.format(cmd_args[0]))


def get_processor(ptr_or_id):
    ptr_or_id = unsigned(ptr_or_id)
    if ptr_or_id < 1024:
        processor_list = kern.GetGlobalVariable('processor_list')
        current_processor = processor_list
        while unsigned(current_processor) > 0:
            if unsigned(current_processor.cpu_id) == ptr_or_id:
                return current_processor
            current_processor = current_processor.processor_list
        raise ArgumentError('no processor found with CPU ID {}'.format(
                ptr_or_id))
    else:
        return kern.GetValueFromAddress(ptr_or_id, 'processor_t')


def get_all_processors():
    processors = []
    processor_list = kern.GetGlobalVariable('processor_list')
    current_processor = processor_list
    while unsigned(current_processor) > 0:
        processors.append(current_processor)
        current_processor = current_processor.processor_list
    return sorted(processors, key=lambda p: p.cpu_id)


def symbolicate(addr):
    return kern.Symbolicate(int(hex(addr), 16))


def PrintCPCDeadline(slot, ctr_deadlines, value):
    for i in range(8):
        deadline = ctr_deadlines.cd_deadlines[i]
        if deadline != 0:
            call = ctr_deadlines.cd_calls[i]
            func = symbolicate(call.cca_func)
            inner_func = ''
            if func == '_cpc_cyclic_trampoline':
                cyclic = cast(call.cca_context, 'cpc_cyclic_t')
                cyclic_func = symbolicate(cyclic.ccyi_info.cci_func)
                inner_func = ' ({})'.format(cyclic_func)
            print('    call {}: {} ({:+d}) -> {}{}'.format(
                    i, deadline, deadline - value, func, inner_func))


def PrintCPCRegs(regs):
    arm64 = kern.arch.startswith('arm64')
    cpmu = regs.cmr_cpmu
    if arm64:
        print('ARM64 expected registers:')
        pmcr0 = cpmu.cacr_pmcr[0]
        pmcr1 = cpmu.cacr_pmcr[1]
        print('  {:>6s} = 0x{:016x}, {:>6s} = 0x{:016x}'.format(
                'PMCR0', pmcr0, 'PMCR1', pmcr1))
        pmesr0 = cpmu.cacr_pmesr[0]
        pmesr1 = cpmu.cacr_pmesr[1]
        print('  {:>6s} = 0x{:016x}, {:>6s} = 0x{:016x}'.format(
                'PMESR0', pmesr0, 'PMESR1', pmesr1))
    else:
        print('Intel expected registers:')
        global_ctrl = cpmu.cxcr_global_ctrl
        fixed_ctrl = cpmu.cxcr_fixed_ctrl
        print('  {:>12s} = 0x{:016x}, {:>12s} = 0x{:016x}'.format(
                'GLOBAL_CTRL', global_ctrl, 'FIXED_CTRL', fixed_ctrl))
        evtsel = cpmu.cxcr_evtsel
        print('  {:>12s} = 0x{:016x}, {:>12s} = 0x{:016x}'.format(
                'EVTSEL0', evtsel[0], 'EVTSEL1', evtsel[1]))
        print('  {:>12s} = 0x{:016x}, {:>12s} = 0x{:016x}'.format(
                'EVTSEL2', evtsel[2], 'EVTSEL3', evtsel[3]))


def PrintCPCSet(cpmu_set, print_cyclics, O):
    print('Set 0x{:x} has {} events, {} cyclics'.format(unsigned(cpmu_set),
            cpmu_set.cst_event_count, cpmu_set.cst_cyclic_count))
    if cpmu_set.cst_events:
        events_header = '{:>5} {:>4} {:>18} {:>7}'.format('event', 'slot', 'selector', 'flags')
        with O.table(events_header):
            for i in range(cpmu_set.cst_event_count):
                event_select = cpmu_set.cst_events[i]
                print('{:>5d} {:>4d} 0x{:016x} 0x{:05x}'.format(
                        i, event_select.ces_slot, event_select.ces_selector,
                        event_select.ces_flags))
    elif cpmu_set.cst_event_count > 0:
        print('warning: events are NULL, but non-zero count')
    if print_cyclics:
        with O.table(cyclic_header):
            for i in range(cpmu_set.cst_cyclic_count):
                cyclic = cpmu_set.cst_cyclics[i]
                PrintCPCCyclic(cyclic, O=O)
    PrintCPCRegs(cpmu_set.cst_regs)


def PrintCPCCall(call, O):
    deadline_index = '-'
    for i in range(8):
        deadline_call = call.cca_deadlines.cd_calls[i]
        if deadline_call and unsigned(deadline_call) == addressof(call):
            deadline_index = str(i)
    print(O.format('0x{:16x} {:>8s} {:5d}',
            addressof(call), deadline_index, unsigned(call.cca_state)))


def PrintCPCCyclic(cyclic, O):
    info = cyclic.ccyi_info
    func = symbolicate(info.cci_func)
    ret = []
    print(O.format('0x{:>16x} {:>4d} {:>20,} {:>30s} {:>5d} {:>5d}',
            unsigned(cyclic), info.cci_slot, info.cci_period, func, unsigned(cyclic.ccyi_state),
            cyclic.ccyi_call_count))
    with O.table(call_header, indent=True):
        for i in range(cyclic.ccyi_call_count):
            PrintCPCCall(cyclic.ccyi_calls[i], O=O)


def PrintCPCGlobalState(O):
    event_policy = kern.GetGlobalVariable('_cpc_event_policy')
    print('Event policy: ' + GetEnumName('cpc_event_policy_t', event_policy))
    sharing = kern.GetGlobalVariable('_cpc_sharing')
    print('     Sharing: ' + GetEnumName('cpc_sharing_t', sharing))
    notify = kern.GetGlobalVariable('_cpc_pm_notify')
    if notify:
        notify_sym = kern.Symbolicate(int(hex(notify), 16))
        print(' Notify func: 0x{:016x} ({:s})'.format(notify, notify_sym))

    active_sets = kern.GetGlobalVariable('_cpc_active_sets')
    cpmu_set = active_sets[GetEnumValue('cpc_hw_t', 'CPC_HW_CPMU')]
    if cpmu_set:
        print('active set:')
        PrintCPCSet(cpmu_set, print_cyclics=False, O=O)
    else:
        print('init regs:')
        PrintCPCRegs(kern.GetGlobalVariable('cpc_machine_regs_init'))

    active_cyclics = kern.GetGlobalVariable('_cpc_active_cyclics')
    active_cyclics_count = kern.GetGlobalVariable('_cpc_active_cyclics_count')
    if active_cyclics_count > 0:
        with O.table(cyclic_header):
            for i in range(active_cyclics_count):
                PrintCPCCyclic(active_cyclics[i], O=O)



def CPCProcessor(pr_ptrs_or_ids, cmd_options={}, O=None):  # noqa: E741
    if '-A' in cmd_options:
        prs = get_all_processors()
    else:
        prs = [get_processor(p) for p in pr_ptrs_or_ids]

    pmc_header = '{:3s} {:3s} {:>20s} {:>20s}'.format(
            'cpu', 'pmc', 'sum', 'last')
    print('counters:')
    with O.table(pmc_header):
        for pr in prs:
            cpu_data = GetCpuDataForCpuID(pr.cpu_id)
            cpu = pr.cpu_id
            cpc = cpu_data.cpu_cpc
            for i in range(10):
                ctr = cpc.ccp_cpmu_counters[i]
                if hasattr(ctr, 'cctr_wrap_count'):
                    wraps = ctr.cctr_wrap_count
                    wrap_fmt = 'd'
                else:
                    wraps = '-'
                    wrap_fmt = 's'
                if ctr.cctr_sum != 0 or ctr.cctr_prev_value != 0:
                    sum = ctr.cctr_sum
                    last = ctr.cctr_prev_value
                    if last > (1 << 62):
                        last = 0 - ((1 << 63) - last)
                    print(O.format('{:3d} {:3d} {:20,} {:20,} {:6' + wrap_fmt + '}',
                            cpu, i, sum, last, wraps))

    recount_header = '{:3s} {:>20s} {:>5s} {:>20s} {:>5s} {:>5s} {:>8s}'.format(
            'cpu', 'cycles-delta', 'cyc%', 'insns-delta', 'ins%', 'ipc', 'pmis')
    print('cross-referencing with recount:')
    with O.table(recount_header):
        for pr in prs:
            cpu_data = GetCpuDataForCpuID(pr.cpu_id)
            cpu = pr.cpu_id
            cpc = cpu_data.cpu_cpc
            snap = pr.pr_recount.rpr_snap
            if hasattr(snap, "rsn_cpu_counts"):
                recount_cycles = snap.rsn_cpu_counts.cycles
                recount_insns = snap.rsn_cpu_counts.instrs
                cpc_cycles = cpc.ccp_cpmu_counters[0].cctr_sum
                cpc_insns = cpc.ccp_cpmu_counters[1].cctr_sum
                cycles = cpc_cycles - recount_cycles
                cycles_pct = cycles / cpc_cycles * 100
                insns = cpc_insns - recount_insns
                insns_pct = insns / cpc_insns * 100
                if cycles == 0:
                    ipc = 0
                else:
                    ipc = insns / cycles
                pmis = cpu_data.cpu_stat.pmi_cnt_wake
                print(O.format(
                        '{:3d} {:+20,} {:5.2f} {:+20,} {:5.2f} {:5.3f} {:8,}',
                        cpu, cycles, cycles_pct, insns, insns_pct, ipc, pmis))

    pr_diags = []
    for pr in prs:
        try:
            diags = kern.PERCPU_GET('_cpc_percpu_diags', pr.cpu_id)
            if diags.cpcd_prev_pmcr0 != 0:
                pr_diags.append(
                        (pr.cpu_id, diags.cpcd_prev_pmcr0, diags.cpcd_last_pmcr0_func))
        except ValueError:
            pass

    if pr_diags:
        print('PMCR0 breadcrumbs:')
        diags_header = '{:3s} {:>18s} {:>30s}'.format('cpu', 'pmcr0', 'pmcr0-func')
        with O.table(diags_header):
            for cpu, pmcr0, pmcr0_func in pr_diags:
                func = '-'
                if pmcr0_func:
                    func = str(pmcr0_func)
                print(O.format('{:3d} 0x{:016x} {:>30s}', cpu, pmcr0, func))

    deadline_header = '{:3s} {:3s} {:>20} {:>20s} {:>30s} {:>18s}'.format(
            'cpu', 'pmc', 'deadline', 'delta', 'func', 'call')
    print('deadlines:')
    with O.table(deadline_header):
        for pr in prs:
            cpu_data = GetCpuDataForCpuID(pr.cpu_id)
            cpu = pr.cpu_id
            cpc = cpu_data.cpu_cpc
            for i in range(10):
                ctr = cpc.ccp_cpmu_counters[i]
                sum = ctr.cctr_sum
                ctr_deadlines = cpc.ccp_cpmu_deadlines[i]
                for j in range(8):
                    deadline = ctr_deadlines.cd_deadlines[j]
                    if deadline != 0:
                        call = ctr_deadlines.cd_calls[j]
                        func = symbolicate(call.cca_func)
                        if func == '_cpc_cyclic_trampoline':
                            cyclic = cast(call.cca_context, 'cpc_cyclic_t')
                            cyclic_func = symbolicate(cyclic.ccyi_info.cci_func)
                            func = '^' + cyclic_func
                        print(O.format(
                                '{:3d} {:3d} {:20,} {:+20,} {:>30s} 0x{:016x}',
                                cpu, i, deadline, deadline - sum, func, unsigned(call)))


def PrintKPCState(O=None):
    kpc_global = kern.GetGlobalVariable('g_kpc')
    kpc_pm_mask = kpc_global.pwr_mgmt_pmc_mask
    if kpc_pm_mask:
        print('Power management:')
        print('  PMC mask: 0x{:x}'.format(kpc_pm_mask))
        custom = unsigned(kpc_global.pwr_mgmt_custom_config) != 0
        print('    Custom: {}'.format('true' if custom else 'false'))

    print('Running:')
    print('    Classes: 0x{:x}'.format(kpc_global.running_class_mask))
    print('   PMC mask: 0x{:x}'.format(kpc_global.running_pmc_mask))
    with O.table('{:>8} {:>18}'.format('kpc-slot', 'config')):
        for i in range(27):
            config = kpc_global.configs[i]
            if config:
                print('{:>8} 0x{:>016x}'.format(i, config))

    print('            Set: 0x{:>016x}'.format(kpc_global.set))
    set_applied = unsigned(kpc_global.set_applied) != 0
    print('    Set applied: {}'.format('true' if set_applied else 'false'))
    set_out_of_date = unsigned(kpc_global.set_out_of_date) != 0
    print('Set out-of-date: {}'.format('true' if set_out_of_date else 'false'))

    kperf_actionv = kern.GetGlobalVariable('actionv')
    with O.table('{:>8} {:>6} {:>8} {:>12}'.format('kpc-slot', 'action', 'samplers', 'period')):
        for i in range(10):
            actionid = kpc_global.actionids[i]
            period = kpc_global.periods[i]
            if actionid != 0 or period != 0:
                print('{:>8d} {:>6d} 0x{:>06x} {:>12}'.format(
                        i, actionid,
                        kperf_actionv[actionid - 1].sample if actionid != 0 else 0,
                        period))


def CPCTriage(cmd_options={}, O=None):  # noqa: E741
    PrintCPCGlobalState(O=O)
    CPCProcessor([], cmd_options={'-A': True}, O=O)

    print('')
    print('kpc:')
    PrintKPCState(O=O)

    # active setting with
    # active owners
