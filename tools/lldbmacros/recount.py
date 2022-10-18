from __future__ import absolute_import, division, print_function

from xnu import *


def validate_args(opts, valid_flags):
    valid_flags = set(valid_flags)
    for k in opts.keys():
        if k[1:] not in valid_flags:
            raise ArgumentError('-{} not supported in subcommand'.format(k))


@lldb_command('recount', 'AF:MT', fancy=True)
def Recount(cmd_args=None, cmd_options={}, O=None):  # noqa: E741
    """ Inspect counters maintained by the Recount subsystem on various resource
        aggregators, like tasks or threads.

        recount task [-TM] <task_t> [...] | -F <task_name>
        recount thread [-M] <thread_t> [...]
        recount coalition [-M] <coalition_t> [...]
        recount processor [-ATM] [<processor_t-or-cpu-id>] [...]

        Options:
            -T : break out active threads for a task or processor
            -M : show times in the Mach timebase
            -A : show all processors

        Diagnostic macros:
            recount diagnose task <task_t>
                - Ensure resource accounting consistency in a task.
            recount triage
                - Print out statistics useful for general panic triage.

    """
    if not cmd_args:
        raise ArgumentError('subcommand required')

    if cmd_args[0] == 'coalition':
        validate_args(cmd_options, ['M'])
        RecountCoalition(cmd_args[1:], cmd_options=cmd_options, O=O)
    elif cmd_args[0] == 'task':
        validate_args(cmd_options, ['F', 'M', 'T'])
        RecountTask(cmd_args[1:], cmd_options=cmd_options, O=O)
    elif cmd_args[0] == 'thread':
        validate_args(cmd_options, ['M'])
        RecountThread(cmd_args[1:], cmd_options=cmd_options, O=O)
    elif cmd_args[0] == 'processor':
        validate_args(cmd_options, ['A', 'M', 'T'])
        RecountProcessor(cmd_args[1:], cmd_options=cmd_options, O=O)
    elif cmd_args[0] == 'diagnose':
        RecountDiagnose(cmd_args[1:], cmd_options=cmd_options, O=O)
    elif cmd_args[0] == 'triage':
        validate_arg(cmd_options, [])
        RecountTriage(cmd_options=cmd_options, O=O)
    else:
        raise ArgumentError('{}: invalid subcommand'.format(cmd_args[0]))


def scale_suffix(val, unit=''):
    si_units = [
            (1e21, 'Z'), (1e18, 'E'), (1e15, 'P'), (1e12, 'T'), (1e9, 'B'),
            (1e6, 'M'), (1e3, 'k'), (1, ' '), (1e-3, 'm'), (1e-6, 'u'),
            (1e-9, 'n')]
    scale, sfx = (1, '')
    for (si_scale, si_sfx) in si_units:
        if val >= si_scale:
            scale, sfx = (si_scale, si_sfx)
            break
    return '{:>7.3f}{:<1s}{}'.format(val / scale, sfx, unit)


class RecountSum(object):
    """
    Accumulate usage counters.
    """

    def __init__(self, mach_times=False):
        self._mach_times = mach_times
        self._user_time_mach = 0
        self._system_time_mach = 0
        self._instructions = 0
        self._cycles = 0
        self._energy_nj = 0
        self._valid_count = 0

    def add_usage(self, usage):
        self._user_time_mach += unsigned(usage.ru_user_time_mach)
        self._system_time_mach += unsigned(usage.ru_system_time_mach)
        if hasattr(usage, 'ru_cycles'):
            self._instructions += unsigned(usage.ru_instructions)
            self._cycles += unsigned(usage.ru_cycles)
            if unsigned(usage.ru_cycles) != 0:
                self._valid_count += 1
        if hasattr(usage, 'ru_energy_nj'):
            self._energy_nj += unsigned(usage.ru_energy_nj)

    def user_sys_times(self):
        return (self._user_time_mach, self._system_time_mach)

    def div_valid(self, numer, denom):
        if self._valid_count == 0 or denom == 0:
            return 0
        return numer / denom

    def _convert_time(self, time):
        if self._mach_times:
            return time
        return kern.GetNanotimeFromAbstime(time) / 1e9

    def fmt_args(self):
        time_ns = kern.GetNanotimeFromAbstime(
                self._system_time_mach + self._user_time_mach)
        power_w = self._energy_nj / time_ns if time_ns != 0 else 0
        return [
                self._convert_time(self._system_time_mach),
                self._convert_time(self._user_time_mach),
                scale_suffix(self._cycles),
                self.div_valid(self._cycles, time_ns),
                scale_suffix(self._instructions),
                self.div_valid(self._cycles, self._instructions),
                scale_suffix(self._energy_nj / 1e9, 'J'),
                scale_suffix(power_w, 'W')]

    def fmt_basic_args(self):
        return [
                self._convert_time(self._system_time_mach),
                self._convert_time(self._user_time_mach),
                self._cycles,
                self._instructions,
                self._energy_nj / 1e9]



class RecountPlan(object):
    """
    Format tracks and usage according to a plan.
    """

    def __init__(self, name, mach_times=False):
        self._mach_times = mach_times
        self._group_names = []
        self._group_column = None

        plan = kern.GetGlobalVariable('recount_' + name + '_plan')
        topo = plan.rpl_topo
        if topo == GetEnumValue('recount_topo_t::RCT_TOPO_CPU'):
            self._group_column = 'cpu'
            self._group_count = unsigned(kern.globals.real_ncpus)
            self._group_names = [
                    'cpu-{}'.format(i) for i in range(self._group_count)]
        elif topo == GetEnumValue('recount_topo_t::RCT_TOPO_CPU_KIND'):
            if kern.arch.startswith('arm64'):
                self._group_column = 'cpu-kind'
                cluster_mask = int(kern.globals.topology_info.cluster_types)
                self._group_count = bin(cluster_mask).count('1')
                self._group_names = [
                        GetEnumName('recount_cpu_kind_t', i)[8:][:4]
                        for i in range(self._group_count)]
            else:
                self._group_count = 1
        elif topo == GetEnumValue('recount_topo_t::RCT_TOPO_SYSTEM'):
            self._group_count = 1
        else:
            raise RuntimeError('{}: Unexpected recount topography', topo)

    def time_fmt(self):
        return '{:>12d}' if self._mach_times else '{:>12.05f}'

    def _usage_fmt(self):
        prefix = '{n}{t} {t}'.format(
                t=self.time_fmt(), n='{:>8s} ' if self._group_column else '')
        return prefix + ' {:>8s} {:>7.3g} {:>8s} {:>5.03f} {:>9s} {:>9s}'

    def usages(self, usages):
        for i in range(self._group_count):
            yield usages[i]

    def track_usages(self, tracks):
        for i in range(self._group_count):
            yield tracks[i].rt_usage

    def usage_header(self):
        fmt = '{:>12s} {:>12s} {:>8s} {:>7s} {:>8s} {:>5s} {:>9s} {:>9s}'.format(
                'sys-time', 'user-time', 'cycles', 'GHz', 'insns', 'CPI',
                'energy', 'power',)
        if self._group_column:
            fmt = '{:>8s} '.format(self._group_column) + fmt
        return fmt

    def format_usage(self, usage, name=None, sum=None, O=None):
        usr_time = unsigned(usage.ru_user_time_mach)
        usr_time_ns = kern.GetNanotimeFromAbstime(usr_time)
        sys_time = unsigned(usage.ru_system_time_mach)
        sys_time_ns = kern.GetNanotimeFromAbstime(sys_time)
        all_time_ns = usr_time_ns + sys_time_ns
        if not self._mach_times:
            usr_time = usr_time_ns / 1e9
        if not self._mach_times:
            sys_time = sys_time_ns / 1e9
        if hasattr(usage, 'ru_cycles'):
            cycles = unsigned(usage.ru_cycles)
            freq = cycles / all_time_ns if all_time_ns != 0 else 0
            insns = unsigned(usage.ru_instructions)
            cpi = cycles / insns if insns != 0 else 0
        else:
            cycles = 0
            freq = 0
            insns = 0
            cpi = 0
        if hasattr(usage, 'ru_energy_nj'):
            energy_nj = unsigned(usage.ru_energy_nj)
            time_ns = usr_time_ns + sys_time_ns
            if time_ns != 0:
                power_w = energy_nj / time_ns
            else:
                power_w = 0
        else:
            energy_nj = 0
            power_w = 0
        if sum:
            sum.add_usage(usage)

        args = [
                sys_time, usr_time, scale_suffix(cycles), freq,
                scale_suffix(insns), cpi, scale_suffix(energy_nj / 1e9, 'J'),
                scale_suffix(power_w, 'W')]
        if self._group_column:
            args.insert(0, name)

        return O.format(self._usage_fmt(), *args)

    def format_sum(self, sum, O=None):
        return O.format(self._usage_fmt(), '*', *sum.fmt_args())

    def format_usages(self, usages, O=None):  # noqa: E741
        sum = RecountSum(self._mach_times) if self._group_count > 1 else None
        str = ''
        for (i, usage) in enumerate(self.usages(usages)):
            name = self._group_names[i] if i < len(self._group_names) else None
            str += self.format_usage(usage, name=name, sum=sum, O=O) + '\n'
        if sum:
            str += self.format_sum(sum, O=O)
        return str

    def format_tracks(self, tracks, newlines=True, O=None):  # noqa: E741
        sum = RecountSum(self._mach_times) if self._group_count > 1 else None
        str = ''
        nl = '\n' if newlines else ''
        for (i, usage) in enumerate(self.track_usages(tracks)):
            name = self._group_names[i] if i < len(self._group_names) else None
            str += self.format_usage(usage, name=name, sum=sum, O=O) + nl
        if sum:
            str += self.format_sum(sum, O=O)
        return str

    def sum_usages(self, usages, sum=None):
        if sum is None:
            sum = RecountSum(mach_times=self._mach_times)
        for usage in self.usages(usages):
            sum.add_usage(usage)
        return sum

    def sum_tracks(self, tracks, sum=None):
        if sum is None:
            sum = RecountSum(mach_times=self._mach_times)
        for usage in self.track_usages(tracks):
            sum.add_usage(usage)
        return sum


def GetTaskTerminatedUserSysTime(task):
    plan = RecountPlan('task_terminated')
    sum = RecountSum()
    for usage in plan.usages(task.tk_recount.rtk_terminated):
        sum.add_usage(usage)
    return sum.user_sys_times()


def GetThreadUserSysTime(thread):
    plan = RecountPlan('thread')
    sum = RecountSum()
    for usage in plan.track_usages(thread.th_recount.rth_lifetime):
        sum.add_usage(usage)
    return sum.user_sys_times()


def print_threads(plan, thread_ptrs, indent=False, O=None):  # noqa: E741
    for thread_ptr in thread_ptrs:
        thread = kern.GetValueFromAddress(thread_ptr, 'thread_t')
        print('{}thread 0x{:x} 0x{:x} {}'.format(
                '    ' if indent else '', unsigned(thread.thread_id),
                unsigned(thread), GetThreadName(thread)))
        with O.table(plan.usage_header(), indent=indent):
            print(plan.format_tracks(thread.th_recount.rth_lifetime, O=O))


def RecountThread(
        thread_ptrs, cmd_options={}, indent=False, O=None):  # noqa: E741
    plan = RecountPlan('thread', mach_times='-M' in cmd_options)
    print_threads(plan, thread_ptrs, indent=indent, O=O)


def get_task_age_ns(task):
    start_abs = GetProcStartAbsTimeForTask(task)
    if start_abs is not None:
        return kern.GetNanotimeFromAbstime(GetRecentTimestamp() - start_abs)
    return None


def print_task_description(task):
    task_name = GetProcNameForTask(task)
    task_age_ns = get_task_age_ns(task)
    if task_age_ns is not None:
        duration_desc = '{:.3f}s'.format(task_age_ns / 1e9)
    else:
        duration_desc = '-s'
    print('task 0x{:x} {} ({} old)'.format(
            unsigned(task), task_name, duration_desc))


def RecountTask(task_ptrs, cmd_options={}, O=None):  # noqa: E741
    if '-F' in cmd_options:
        tasks = FindTasksByName(cmd_options['-F'])
    else:
        tasks = [kern.GetValueFromAddress(t, 'task_t') for t in task_ptrs]
    mach_times = '-M' in cmd_options
    plan = RecountPlan('task', mach_times=mach_times)
    terminated_plan = RecountPlan('task_terminated', mach_times=mach_times)
    active_threads = '-T' in cmd_options
    if active_threads:
        thread_plan = RecountPlan('thread', mach_times=mach_times)
    for task in tasks:
        print_task_description(task)
        with O.table(plan.usage_header()):
            print(plan.format_tracks(task.tk_recount.rtk_lifetime, O=O))
            if active_threads:
                threads = [unsigned(t) for t in IterateQueue(
                        task.threads, 'thread *', 'task_threads')]
                print_threads(thread_plan, threads, indent=True, O=O)
        print('task (terminated threads) 0x{:x} {}'.format(
                unsigned(task), task_name))
        with O.table(terminated_plan.usage_header()):
            print(terminated_plan.format_usages(
                    task.tk_recount.rtk_terminated, O=O))


def RecountCoalition(coal_ptrs, cmd_options={}, O=None):  # noqa: E741
    plan = RecountPlan('coalition', mach_times='-M' in cmd_options)
    coals = [kern.GetValueFromAddress(c, 'coalition_t') for c in coal_ptrs]
    for coal in coals:
        print('coalition 0x{:x} {}'.format(unsigned(coal), unsigned(coal.id)))
        with O.table(plan.usage_header()):
            print(plan.format_usages(coal.r.co_recount.rco_exited, O=O))


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


def RecountProcessor(pr_ptrs_or_ids, cmd_options={}, O=None):  # noqa: E741
    mach_times = '-M' in cmd_options
    plan = RecountPlan('processor', mach_times=mach_times)
    if '-A' in cmd_options:
        prs = get_all_processors()
    else:
        prs = [get_processor(p) for p in pr_ptrs_or_ids]
    active_threads = '-T' in cmd_options
    if active_threads:
        thread_plan = RecountPlan('thread', mach_times=mach_times)
    hdr_prefix = '{:>18s} {:>4s} {:>4s} '.format('processor', 'cpu', 'kind',)
    hdr_suffix = ' {:>12s} {:>12s} {:>8s}'.format(
            'idle-time', 'total-time', 'idle-pct')
    with O.table(hdr_prefix + plan.usage_header() + hdr_suffix):
        for pr in prs:
            usage = pr.pr_recount.rpr_active.rt_usage
            idle_time = pr.pr_recount.rpr_idle_time_mach
            total_time = (
                    usage.ru_system_time_mach + usage.ru_user_time_mach +
                    idle_time)
            if not mach_times:
                idle_time = kern.GetNanotimeFromAbstime(idle_time) / 1e9
                total_time = kern.GetNanotimeFromAbstime(total_time) / 1e9
            kind = 'SMP'
            pset = pr.processor_set
            if unsigned(pset.pset_cluster_type) == 1:
                kind = 'E'
            elif unsigned(pset.pset_cluster_type) == 2:
                kind = 'P'

            prefix = '{:<#018x} {:>4d} {:>4s} '.format(
                    unsigned(pr), pr.cpu_id, kind)
            suffix = (
                    ' ' + plan.time_fmt().format(idle_time) + ' ' +
                    plan.time_fmt().format(total_time) +
                    ' {:>7.2f}%'.format(idle_time / total_time * 100))
            O.write(prefix + plan.format_usage(usage, O=O) + suffix + '\n')
            if active_threads:
                active_thread = unsigned(pr.active_thread)
                if active_thread != 0:
                    print_threads(
                            thread_plan, [active_thread], indent=True, O=O)


@header('{:>4s} {:>20s} {:>20s} {:>20s}'.format(
        'cpu', 'time-mach', 'cycles', 'insns'))
def GetRecountSnapshot(cpu, snap, O=None):
    (insns, cycles, energy) = (0, 0, 0)
    if hasattr(snap, 'rsn_cycles'):
        (insns, cycles) = (snap.rsn_insns, snap.rsn_cycles)
    return O.format(
            '{:4d} {:20d} {:20d} {:20d}', cpu, snap.rsn_time_mach,
            cycles, insns)


def GetRecountProcessorState(pr):
    state_time = pr.pr_recount.rpr_state_last_abs_time
    state = state_time >> 63
    return ('I' if state == 1 else 'A', state_time & ~(0x1 << 63))


@header('{:>20s} {:>4s} {:>6s} {:>18s} {:>18s} {:>18s} {:>18s} {:>18s}'.format(
        'processor', 'cpu', 'state', 'last-idle-change', 'last-user-change',
        'last-disp', 'since-idle-change', 'since-user-change'))
def GetRecountProcessorDiagnostics(pr, cur_time, O=None):
    (state, time) = GetRecountProcessorState(pr)
    cpu_id = unsigned(pr.cpu_id)
    snap = kern.PERCPU_GET('_snaps_percpu', cpu_id)
    last_usrchg = snap.rsn_time_mach
    since_usrchg = cur_time - last_usrchg
    last_disp = '{}{:>d}'.format(
            '*' if cur_time == unsigned(pr.last_dispatch) else '',
            pr.last_dispatch)
    return O.format(
            '{:>#20x} {:4d} {:>6s} {:>18d} {:>18d} {:>18s} {:>18d} {:>18d}',
            unsigned(pr), cpu_id, state, time, last_usrchg, last_disp,
            cur_time - time, since_usrchg)


@header('{:>12s} {:>12s} {:>12s} {:>20s} {:>20s} {:>12s}'.format(
        'group', 'sys-time', 'user-time', 'cycles', 'insns', 'energy'))
def RecountDiagnoseTask(task_ptrs, cmd_options={}, O=None):  # noqa: E74
    if '-F' in cmd_options:
        tasks = FindTasksByName(cmd_options['-F'])
    else:
        tasks = [kern.GetValueFromAddress(t, 'task_t') for t in task_ptrs]

    line_fmt = '{:12s} = {:10.3f}'
    row_fmt = '{:>12s} {:>12.3f} {:>12.3f} {:>20d} {:20d} {:12.3f}'

    task_plan = RecountPlan('task', mach_times=False)
    term_plan = RecountPlan('task_terminated', mach_times=False)
    thread_plan = RecountPlan('thread', mach_times=False)
    for task in tasks:
        print_task_description(task)
        with O.table(RecountDiagnoseTask.header):
            task_sum = task_plan.sum_tracks(task.tk_recount.rtk_lifetime)
            print(O.format(row_fmt, 'task', *task_sum.fmt_basic_args()))

            term_sum = term_plan.sum_usages(task.tk_recount.rtk_terminated)
            print(O.format(row_fmt, 'terminated', *term_sum.fmt_basic_args()))

            threads_sum = RecountSum(mach_times=False)
            for thread in IterateQueue(task.threads, 'thread *', 'task_threads'):
                usr_time, sys_time = GetThreadUserSysTime(thread)
                threads_sum_mach += usr_time + sys_time

            threads_sum_ns = kern.GetNanotimeFromAbstime(threads_sum_mach)
            print(line_fmt.format('threads CPU', threads_sum_ns / 1e9))

            all_threads_sum_ns = threads_sum_ns + terminated_threads_sum_ns
            print(line_fmt.format('all threads CPU', all_threads_sum_ns / 1e9))

            print(line_fmt.format('discrepancy', task_sum_ns - all_threads_sum_ns))


def RecountDiagnose(cmd_args=[], cmd_options={}, O=None):  # noqa: E741
    if not cmd_args:
        raise ArgumentError('diagnose subcommand required')

    if cmd_args[0] == 'task':
        validate_args(cmd_options, ['F'])
        RecountDiagnoseTask(cmd_args[0], cmd_options=cmd_options, O=O)
    else:
        raise ArgumentError('{}: invalid diagnose subcommand'.format(
                cmd_args[0]))


def RecountTriage(cmd_options={}, O=None):  # noqa: E741
    prs = get_all_processors()
    print('processors')
    with O.table(GetRecountProcessorDiagnostics.header, indent=True):
        max_dispatch = max([unsigned(pr.last_dispatch) for pr in prs])
        for pr in prs:
            print(GetRecountProcessorDiagnostics(
                    pr, cur_time=max_dispatch, O=O))

    print('snapshots')
    with O.table(GetRecountSnapshot.header, indent=True):
        ncpus = unsigned(kern.globals.real_ncpus)
        for i in range(ncpus):
            snap = kern.PERCPU_GET('_snaps_percpu', i)
            print(GetRecountSnapshot(i, snap, O=O))
