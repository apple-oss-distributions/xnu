from xnu import *


@lldb_type_summary(['struct os_refgrp *'])
@header("{0: <18s} {1: <46s} {2: <9s} {3: <9s} {4: <9s} {5: <18s}"
        .format("os_refgrp", "name", "count", "retain", "release", "log"))
def GetOSRefGrpSummary(refgrp):
    """ Summarizes os_refgrp structure.
        params: refgrp: value - value object representing an os_refgrp in
        kernel
        returns: str - summary of the os reference group
    """

    format_string = "{0: <#18x} {1: <46s} {2: <9d} {3: <9d} {4: <9d} {5: <#18x}"

    return format_string.format(refgrp, str(refgrp.grp_name),
                   refgrp.grp_count, refgrp.grp_retain_total,
                   refgrp.grp_release_total, refgrp.grp_log)

# Macro: showosrefgrp
@lldb_command('showosrefgrp')
def ShowOSRefGrpHelper(cmd_args=None):
    """ Display a summary of the specified os reference group
        Usage: showosrefgrp <refgrp address>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    refgrp = kern.GetValueFromAddress(cmd_args[0], 'struct os_refgrp *')
    if not refgrp:
        raise ArgumentError("Unknown arguments: {:s}".format(cmd_args[0]))

    print(GetOSRefGrpSummary.header)
    print(GetOSRefGrpSummary(refgrp))
# EndMacro: showosrefgrp


# Macro: showosrefgrphierarchy
@lldb_command('showosrefgrphierarchy')
def ShowOSRefGrpHierarchy(cmd_args=None):
    """ Display the os reference group hiearchy associated with the specified
        os reference group
        Usage: showosrefgrphierarchy <refgrp address>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    refgrp = kern.GetValueFromAddress(cmd_args[0], 'struct os_refgrp *')
    if not refgrp:
        raise ArgumentError("Unknown arguments: {:s}".format(cmd_args[0]))

    grps = []

    parent = refgrp
    while parent != 0:
        grps.insert(0, parent)
        parent = parent.grp_parent

    for grp in grps:
        print(GetOSRefGrpSummary(grp))
# EndMacro: showosrefgrphierarchy

# Macro: showglobaltaskrefgrps
@lldb_command('showglobaltaskrefgrps')
def ShowGlobalTaskRefGrps(cmd_args=None):
    """ Display all global task reference count groups
        Usage: showglobaltaskrefgrps
    """

    print(GetOSRefGrpSummary.header)

    # First print global groups
    task_refgrp = kern.globals.task_refgrp
    count = sizeof(task_refgrp) // sizeof('struct os_refgrp *')
    i = 0
    while i < count:
        if task_refgrp[i].grp_retain_total != 0:
            print(GetOSRefGrpSummary(task_refgrp[i]))
        i += 1

    # Then print kext groups
    count = kern.globals.sKextAccountsCount
    kext_accounts_base = addressof(kern.globals.sKextAccounts[0])
    for i in range(count):
        kextaccount = GetObjectAtIndexFromArray(kext_accounts_base, i)
        if not kextaccount.account:
            continue
        task_refgrp = kextaccount.account.task_refgrp

        if task_refgrp.grp_retain_total != 0:
            print(GetOSRefGrpSummary(addressof(task_refgrp)))
# EndMacro: showglobaltaskrefgrps


# Macro: showtaskrefgrps
@lldb_command('showtaskrefgrps')
def ShowTaskRefGrps(cmd_args=None):
    """ Display per-task reference count groups
        Usage: showtaskrefgrps <address of task>
    """

    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Invalid arguments passed.")
    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')

    print(GetOSRefGrpSummary.header)

    grp = tval.ref_group
    if kern.globals.task_refgrp_config == 0:
        count = 2
    if kern.globals.task_refgrp_config == 1:
        count = 8
    if kern.globals.task_refgrp_config == 2:
        count = 0
    i = 0
    while i < count:
        if grp[i].grp_retain_total != 0:
            print(GetOSRefGrpSummary(addressof(grp[i])))
        i += 1

# EndMacro: showtaskrefgrps
