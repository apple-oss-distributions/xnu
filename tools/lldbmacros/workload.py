from xnu import *

@lldb_type_summary(['workload_config_entry_t *'])
@header("{0: <20s} {1: <40s} {2: <18s} {3: <18s}".format("workload", "id", "default phase", "phases"))
def GetWorkloadConfigSummary(workload):
    """ Summarizes workload_config_entry structure
        params: workload: value - value object representing workload_config_entry
        returns: str - summary of the workload object
    """
    format_string = '{0: <#020x} {1: <40s} {2: <#018x} {2: <#018x}'
    return format_string.format(workload, str(workload.wce_id), workload.wce_default, workload.wce_phases)


@lldb_type_summary(['workload_phase_entry_t *'])
@header("{0: <20s} {1: <25s} {2: <10s} {3: <10s} {4: <10s} {5: <20s}".format("phase", "id", "flags", "cflags", "tflags", "criticality offset"))
def GetWorkloadPhaseSummary(phase):
    """ Summarizes workload_phase_entry structure
        params: phase: value - value object representing workload_phase_entry
        returns: str - summary of the workload phase object
    """

    format_string = '{0: <#020x} {1: <25s} {2: <#010x} {3: <#010x} {4: <#010x} {4: <20d} '
    return format_string.format(phase, str(phase.wpe_phase), phase.wpe_config.wc_flags, phase.wpe_config.wc_create_flags, phase.wpe_config.wc_thread_group_flags, phase.wpe_config.wc_criticality_offset)

# Macro: showallworkloadconfig

@lldb_command('showallworkloadconfig')
def ShowAllWorkloadConfig(cmd_args=None, cmd_options={}):
    """  Routine to print the all workload configurations.
         Usage: showallworkloadconfig
    """

    print(GetWorkloadConfigSummary.header)
    table = kern.globals.workload_config_boot.wlcc_hashtbl
    mask = kern.globals.workload_config_boot.wlcc_hash_mask

    if table != 0:
        for i in range(mask + 1):
            for entry in IterateListEntry(table[i], 'wce_link'):
                print(GetWorkloadConfigSummary(entry))

# EndMacro: showallworkloadconfig


# Macro: showworkloadconfig

@lldb_command('showworkloadconfig', 'F:')
def ShowWorkloadConfig(cmd_args=None, cmd_options={}):
    """  Routine to print a summary listing of given workload config
         Usage: showworkloadconfig <address of workload config>
         or   : showworkloadconfig -F <workload config id>
    """

    if "-F" in cmd_options:
        print(GetWorkloadConfigSummary.header)
        table = kern.globals.workload_config_boot.wlcc_hashtbl
        mask = kern.globals.workload_config_boot.wlcc_hash_mask

        if table != 0:
            for i in range(mask + 1):
                for entry in IterateListEntry(table[i], 'wce_link'):
                    if cmd_options['-F'] == str(entry.wce_id):
                        print(GetWorkloadConfigSummary(entry))
                        return
    else:
        if cmd_args is None or len(cmd_args) == 0:
            raise ArgumentError("Invalid arguments passed.")
        entry = kern.GetValueFromAddress(cmd_args[0], 'workload_config_entry_t *')
        print(GetWorkloadConfigSummary.header)
        print(GetWorkloadConfigSummary(entry))

# EndMacro: showworkloadconfig


# Macro: showworkloadconfigphases

@lldb_command('showworkloadconfigphases')
def ShowWorkloadConfigPhases(cmd_args=None, cmd_options={}):
    """  Routine to print the workload configuration phases of the specified workload config.
         Usage: showworkloadconfigphases <workload config>
    """

    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Invalid arguments passed.")

    print(GetWorkloadPhaseSummary.header)

    entry = kern.GetValueFromAddress(cmd_args[0], 'workload_config_entry_t *')
    for phase in IterateListEntry(entry.wce_phases, 'wpe_link'):
            print(GetWorkloadPhaseSummary(phase))

# EndMacro: showworkloadconfigphases

