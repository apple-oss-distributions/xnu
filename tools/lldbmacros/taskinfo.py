from core.cvalue import sizeof, value
from scheduler import GetRecentTimestamp
from xnu import ArgumentError, lldb_command, kern

# Macro: showtasksuspendstats

def ShowTaskSuspendStats(task: value):
    """
    Routine to print out a summary of suspension statistics for a given task
        params:
            task - core.value : a object of type 'task *'
        returns:
            None
    """
    stats = task.t_suspend_stats
    count = stats.tss_count
    suspended = bool(task.suspend_count > 0)
    recent_time = GetRecentTimestamp()
    duration_sec = kern.GetNanotimeFromAbstime(stats.tss_duration) / 1e9
    last_start_sec = kern.GetNanotimeFromAbstime(stats.tss_last_start - recent_time) / 1e9
    last_end_sec = kern.GetNanotimeFromAbstime(stats.tss_last_end - recent_time) / 1e9
    header_fmt = '{:<20s} {:<20s} {:<20s} {:<20s} {:<20s} {:<20s}'
    header = header_fmt.format('task', 'suspended', 'total_suspensions', 'total_duration(s)', 'last_start_ago(s)', 'last_end_ago(s)')
    print(header)
    print(f'{task: <#020x} {str(suspended).lower():<20s} {count:<20d} {duration_sec:<20f} {last_start_sec:<20f} {last_end_sec:<20f}')

@lldb_command('showtasksuspendstats')
def ShowTaskSuspendStatsMacro(cmd_args=None, cmd_options={}):
    """
    Display suspension statistics for a given task
        Usage: showtasksuspendstats <task addr>  (ex. showtasksuspendstats 0x00ataskptr00 )
    """
    if cmd_args is None or len(cmd_args) != 1:
        raise ArgumentError("Invalid argument")
    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    ShowTaskSuspendStats(task)

# EndMacro
# Macro: showtasksuspenders

def ShowTaskSuspendSources(task: value):
    '''
    Print task suspension events for a given task
        params:
            task - core.value : an object of type `task_t`
    '''
    sources = task.t_suspend_sources
    header_fmt = '{:<20s} {:<20s} {:<20s} {:<20s}'
    header = header_fmt.format('procname', 'pid', 'tid', 'time_ago(s)')
    print(header)
    source_count = sizeof(sources) // sizeof(sources[0])
    for i in range(source_count):
        source = sources[i]
        recent_time = GetRecentTimestamp()
        time_ago_sec = kern.GetNanotimeFromAbstime(source.tss_time - recent_time) / 1e9 if source.tss_time != 0 else -1.0
        procname = str(source.tss_procname) if str(source.tss_procname) != '' else 'nil'
        print(f'{procname:<20s} {source.tss_pid:<20d} {source.tss_tid:<20d} {time_ago_sec:<20.3f}')


@lldb_command('showtasksuspendsources')
def ShowTaskSuspendSourcesMacro(cmd_args=None, cmd_options={}):
    '''
    Show info on the most recent suspenders for a given task
        Usage showtasksuspenders <task addr> (ex. showtasksuspenders 0x00ataskptr00 )
    '''
    if cmd_args is None or len(cmd_args) != 1:
        raise ArgumentError("Invalid argument")
    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    ShowTaskSuspendSources(task)

# EndMacro
