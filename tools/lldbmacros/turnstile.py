from core import xnu_format, iter_SLIST_HEAD
from xnu import *
import sys, shlex
from utils import *
from waitq import *
import kmemory
import xnudefines

@lldb_type_summary(['struct turnstile *'])
@header("{0: <20s} {1: <5s} {2: <20s} {3: <8s} {4: <8s} {5: <23s} {6: <20s} {7: <10s} {8: <10s} {9: <20s} {10: <20s}".format(
    "turnstile", "pri", "waitq", "type", "state", "inheritor", "proprietor", "gen cnt", "prim cnt", "thread", "prev_thread"))
def GetTurnstileSummary(turnstile):
    """ Summarizes the turnstile
        params: turnstile = value of the object of type struct turnstile *
        returns: String with summary of the type.
    """

    ts_v     = turnstile.GetSBValue()
    ts_tg    = ts_v.xGetScalarByName('ts_type_gencount')
    ts_type  = ts_tg & 0xff
    ts_gen   = ts_tg >> 8

    if ts_type == GetEnumValue('turnstile_type_t', 'TURNSTILE_NONE'):
        turnstile_type = "none   "
    elif ts_type == GetEnumValue('turnstile_type_t', 'TURNSTILE_KERNEL_MUTEX'):
        turnstile_type = "knl_mtx"
    elif ts_type == GetEnumValue('turnstile_type_t', 'TURNSTILE_ULOCK'):
        turnstile_type = "ulock  "
    elif ts_type == GetEnumValue('turnstile_type_t', 'TURNSTILE_PTHREAD_MUTEX'):
        turnstile_type = "pth_mtx"
    elif ts_type == GetEnumValue('turnstile_type_t', 'TURNSTILE_SYNC_IPC'):
        turnstile_type = "syn_ipc"
    elif ts_type == GetEnumValue('turnstile_type_t', 'TURNSTILE_WORKLOOPS'):
        turnstile_type = "kqwl   "
    elif ts_type == GetEnumValue('turnstile_type_t', 'TURNSTILE_WORKQS'):
        turnstile_type = "workq  "
    elif ts_type == GetEnumValue('turnstile_type_t', 'TURNSTILE_KNOTE'):
        turnstile_type = "knote  "
    elif ts_type == GetEnumValue('turnstile_type_t', 'TURNSTILE_SLEEP_INHERITOR'):
        turnstile_type = "slp_inh"
    elif ts_type == GetEnumValue('turnstile_type_t', 'TURNSTILE_EPOCH_KERNEL'):
        turnstile_type = "epoch_k"
    elif ts_type == GetEnumValue('turnstile_type_t', 'TURNSTILE_EPOCH_USER'):
        turnstile_type = "epoch_u"
    else:
        turnstile_type = "       "

    ts_state = ts_v.xGetScalarByName('ts_state')
    if ts_state & 0x1:
        turnstile_state = "T"
    elif ts_state & 0x2:
        turnstile_state = "F"
    elif ts_state & 0x4:
        turnstile_state = "H"
    elif ts_state & 0x8:
        turnstile_state = "P"
    else:
        turnstile_state = ""

    ts_inheritor_flags = ts_v.xGetScalarByName('ts_inheritor_flags')
    if ts_inheritor_flags & 0x4:
        inheritor_type = "th"
    elif ts_inheritor_flags & 0x8:
        inheritor_type = "ts"
    elif ts_inheritor_flags & 0x40:
        inheritor_type = "wq"
    else:
        inheritor_type = "--"

    format_str = (
        "{&ts_v: <#020x}"
        " {$ts_v.ts_priority: <5d}"
        " {&ts_v.ts_waitq: <#020x}"
        " {0: <8s}"
        " {1: <8s}"
        " {2: <2s}:{$ts_v.ts_waitq.waitq_inheritor: <#020x}"
        " {$ts_v.ts_proprietor: <#020x}"
        " {3: <10d}"
        " {$ts_v.ts_prim_count: <10d}"
    )
    if hasattr(turnstile, 'ts_thread'):
        format_str += (
            " {$ts_v.ts_thread: <#020x}"
            " {$ts_v.ts_prev_thread: <#020x}"
        )

    return xnu_format(format_str,
        turnstile_type, turnstile_state, inheritor_type, ts_gen,
        ts_v=ts_v)


def PrintTurnstile(turnstile, O=None):
    """ print turnstile and it's free list.
        params:
            turnstile - turnstile to print
    """
    print(GetTurnstileSummary(turnstile))

    """ print turnstile freelist if its not on a thread or freelist """

    waitq = Waitq(addressof(turnstile.ts_waitq))
    if waitq.hasThreads():
        with O.table(GetWaitqSummary.header):
            ShowWaitqHelper(waitq, O=O)

    if turnstile.ts_state & 0x3 == 0:
        needsHeader = True
        for free_turnstile in IterateListEntry(turnstile.ts_free_turnstiles, 'ts_free_elm', 's'):
            if needsHeader:
                print("Turnstile free List:")
                header_str = "    " + GetTurnstileSummary.header
                print(header_str)
                needsHeader = False
            print("    " + GetTurnstileSummary(free_turnstile))

# Macro: showturnstile
@lldb_command('showturnstile', fancy=True)
def ShowTurnstile(cmd_args=None, cmd_options={}, O=None):
    """ show the turnstile and all free turnstiles hanging off the turnstile.
        Usage: (lldb)showturnstile <struct turnstile *>
    """
    if cmd_args is None or len(cmd_args) == 0:
      raise ArgumentError("Please provide arguments")

    turnstile = kern.GetValueFromAddress(cmd_args[0], 'struct turnstile *')
    with O.table(GetTurnstileSummary.header):
        PrintTurnstile(dereference(turnstile), O=O)
# EndMacro: showturnstile

@lldb_command('showturnstilehashtable', fancy=True)
def ShowTurnstileHashTable(cmd_args=None, cmd_options={}, O=None):
    """ show the global hash table for turnstiles.
        Usage: (lldb)showturnstilehashtable
    """
    with O.table(GetTurnstileSummary.header):
        turnstile_htable_buckets = kern.globals.ts_htable_buckets
        for index in range(0, turnstile_htable_buckets):
            turnstile_bucket = GetObjectAtIndexFromArray(kern.globals.turnstile_htable, index)
            for turnstile in iter_SLIST_HEAD(turnstile_bucket.ts_ht_bucket_list.GetSBValue(), 'ts_htable_link'):
                PrintTurnstile(turnstile, O=O)

# Macro: showallturnstiles
@lldb_command('showallturnstiles', fancy=True)
def ShowAllTurnstiles(cmd_args=None, cmd_options={}, O=None):
    """ A macro that walks the list of all allocated turnstile objects and prints them.
        usage: (lldb) showallturnstiles
    """
    with O.table(GetTurnstileSummary.header):
        ts_ty = gettype('struct turnstile')
        for ts in kmemory.Zone("turnstiles").iter_allocated(ts_ty):
            PrintTurnstile(value(ts), O=O)
# EndMacro showallturnstiles

# Macro: showallbusyturnstiles
@lldb_command('showallbusyturnstiles', 'V', fancy=True)
def ShowAllBusyTurnstiles(cmd_args=None, cmd_options={}, O=None):
    """ A macro that walks the list of all allocated turnstile objects
        and prints them.
        usage: (lldb) showallbusyturnstiles [-V]

        -V     Even show turnstiles with no waiters (but with a proprietor)
    """

    verbose = "-V" in cmd_options

    def ts_is_interesting(ts):
        if not ts.xGetScalarByName('ts_proprietor'):
            # not owned by any primitive
            return False
        if verbose:
            return True
        return ts.xGetScalarByPath('.ts_waitq.waitq_prio_queue.pq_root')

    with O.table(GetTurnstileSummary.header):
        ts_ty = gettype('struct turnstile')
        for ts in kmemory.Zone("turnstiles").iter_allocated(ts_ty):
            if ts_is_interesting(ts):
                PrintTurnstile(value(ts), O=O)

# EndMacro showallbusyturnstiles

@lldb_command('showthreadbaseturnstiles', fancy=True)
def ShowThreadInheritorBase(cmd_args=None, cmd_options={}, O=None):
    """ A macro that walks the list of userspace turnstiles pushing on a thread and prints them.
        usage: (lldb) showthreadbaseturnstiles thread_pointer
    """
    if cmd_args is None or len(cmd_args) == 0:
        return O.error('invalid thread pointer')

    thread = kern.GetValueFromAddress(cmd_args[0], "thread_t")
    with O.table(GetTurnstileSummary.header):
        for turnstile in IterateSchedPriorityQueue(thread.base_inheritor_queue, 'struct turnstile', 'ts_inheritor_links'):
            PrintTurnstile(turnstile, O=O)

@lldb_command('showthreadschedturnstiles', fancy=True)
def ShowThreadInheritorSched(cmd_args=None, cmd_options={}, O=None):
    """ A macro that walks the list of kernelspace turnstiles pushing on a thread
        and prints them.
        usage: (lldb) showthreadschedturnstiles thread_pointer
    """
    if cmd_args is None or len(cmd_args) == 0:
        return O.error('invalid thread pointer')

    thread = kern.GetValueFromAddress(cmd_args[0], "thread_t")
    with O.table(GetTurnstileSummary.header):
        for turnstile in IterateSchedPriorityQueue(thread.sched_inheritor_queue, 'struct turnstile', 'ts_inheritor_links'):
            PrintTurnstile(turnstile, O=O)
