#!/usr/bin/env python

""" This file holds all static values that debugging macros need. These are typically object type strings, #defines in C etc.
    The objective is to provide a single place to be the bridge between C code in xnu and the python macros used by lldb.
    If you define a variable which has been copied/referred over from C code and has high chance of changing over time. It would
    be best to define a supporting function of format "populate_<variable_name>". This will help in running them to repopulate.

    Note: The Format of the function has to be populate_<variable_name> so that the automated updating will pick it up.
"""
import os, re

def GetStateString(strings_dict, state):
    """ Turn a dictionary from flag value to flag name and a state mask with
        those flags into a space-separated string of names.

        params:
            strings_dict: a dictionary of flag values to flag names
            state: the value to get the state string of
        return:
            a space separated list of flag names present in state
    """
    max_mask = max(strings_dict.keys())

    first = True
    output = ''
    mask = 0x1
    while mask <= max_mask:
        bit = int(state & mask)
        if bit:
            if bit in strings_dict:
                if not first:
                    output += ' '
                else:
                    first = False
                output += strings_dict[int(state & mask)]
            else:
                output += '{:#x}'.format(mask)
        mask = mask << 1

    return output

KDBG_NOWRAP           = 0x00000002
KDBG_WRAPPED          = 0x00000008
KDBG_TYPEFILTER_CHECK = 0x00400000
KDBG_BUFINIT          = 0x80000000
KDCOPYBUF_COUNT       = 8192
KDS_PTR_NULL          = 0xffffffff
DBG_FUNC_START        = 0x01
DBG_FUNC_END          = 0x02

kdebug_flags_strings = { 0x00100000: 'RANGECHECK',
                         0x00200000: 'VALCHECK',
                         KDBG_TYPEFILTER_CHECK: 'TYPEFILTER_CHECK',
                         KDBG_BUFINIT: 'BUFINIT' }

kperf_samplers_strings = { 1 << 0: 'TH_INFO',
                           1 << 1: 'TH_SNAP',
                           1 << 2: 'KSTACK',
                           1 << 3: 'USTACK',
                           1 << 4: 'PMC_THREAD',
                           1 << 5: 'PMC_CPU',
                           1 << 6: 'PMC_CONFIG',
                           1 << 7: 'MEMINFO',
                           1 << 8: 'TH_SCHED',
                           1 << 9: 'TH_DISP',
                           1 << 10: 'TK_SNAP' }

lcpu_self = 0xFFFE
arm_level2_access_strings = [ " noaccess",
                              " supervisor(readwrite) user(noaccess)",
                              " supervisor(readwrite) user(readonly)",
                              " supervisor(readwrite) user(readwrite)",
                              " noaccess(reserved)",
                              " supervisor(readonly) user(noaccess)",
                              " supervisor(readonly) user(readonly)",
                              " supervisor(readonly) user(readonly)",
                              " "
                             ]

thread_qos_short_strings = { 0: '--',
                             1: 'MT',
                             2: 'BG',
                             3: 'UT',
                             4: 'DF',
                             5: 'IN',
                             6: 'UI',
                             7: 'MG' }

KQWQ_NBUCKETS = 7
KQWL_NBUCKETS = 6

DTYPE_VNODE = 1
DTYPE_SOCKET = 2
DTYPE_PSXSHM = 3
DTYPE_PSXSEM = 4
DTYPE_KQUEUE = 5
DTYPE_PIPE = 6
DTYPE_FSEVENTS = 7
DTYPE_ATALK = 8
DTYPE_NETPOLICY = 9
filetype_strings = { DTYPE_VNODE: 'VNODE',
                     DTYPE_SOCKET: 'SOCKET',
                     DTYPE_PSXSHM: 'PSXSHM',
                     DTYPE_PSXSEM: 'PSXSEM',
                     DTYPE_KQUEUE: 'KQUEUE',
                     DTYPE_PIPE: 'PIPE',
                     DTYPE_FSEVENTS: 'FSEVENTS',
                     DTYPE_ATALK: 'APLTALK',
                     DTYPE_NETPOLICY: 'NETPOLI'
                     }


MACH_PORT_DEAD = 0xffffffffffffffff
IPC_OBJECT_DEAD = MACH_PORT_DEAD

mach_msg_type_descriptor_strings = {0: "PORT", 1: "OOLDESC", 2: "OOLPORTS", 3: "OOLVOLATILE"}

proc_state_strings = ["", "Idle", "Run", "Sleep", "Stop", "Zombie", "Reaping"]
proc_flag_explain_strings = {
        0x00000001: 'may hold advisory locks',
        0x00000002: 'has a controlling tty',
        # Also used to singal 32-bit process.
        0x00000004: 'process is 64 bit',
        0x00000008: 'No SIGCHLD on child stop',
        0x00000010: 'waiting for child exec/exit',
        0x00000020: 'has started profiling',
        0x00000040: 'in select; wakeup/waiting danger',
        0x00000080: 'was stopped and continued',
        0x00000100: 'has set privileges since last exec',
        0x00000200: 'system process: no signals, stats, or swap',
        0x00000400: 'timing out during sleep',
        0x00000800: 'debugged process being traced',
        0x00001000: 'address space layout randomization disabled',
        0x00002000: 'exit in progress',
        0x00004000: 'process has called exec',
        0x00008000: 'owe process an addupc()',
        0x00010000: 'affinity for Rosetta children',
        0x00020000: 'wants to run Rosetta',
        0x00040000: 'has wait() in progress',
        0x00080000: 'checks for OPENEVT flag set on open',
        0x00100000: 'can call vfs_markdependency()',
        0x00200000: 'has called reboot()',
        0x00400000: 'Reserved',
        0x00800000: 'Reserved',
        0x01000000: 'has thread cwd',
        0x02000000: 'Reserved',
        0x04000000: 'process has adopted persona',
        0x08000000: 'Reserved',
        0x10000000: 'no shared libraries',
        0x20000000: 'force quota on root',
        0x40000000: 'no zombies when children exit',
        0x80000000: 'no hangs on remote FS ops'
        }

FSHIFT = 11
FSCALE = 1 << FSHIFT

DBG_TRACE               = 1
DBG_TRACE_INFO          = 2
RAW_VERSION1            = 0x55aa0101
EVENTS_PER_STORAGE_UNIT = 2048

EMBEDDED_PANIC_MAGIC = 0x46554E4B
EMBEDDED_PANIC_STACKSHOT_SUCCEEDED_FLAG = 0x02

MACOS_PANIC_MAGIC = 0x44454544
MACOS_PANIC_STACKSHOT_SUCCEEDED_FLAG = 0x04

TKS_MAGIC = 0x83a83f29

AURR_PANIC_MAGIC = 0x41555252
AURR_PANIC_VERSION = 1

CRASHLOG_PANIC_STRING_LEN = 32
AURR_CRASHLOG_PANIC_VERSION = 2

# File:EXTERNAL_HEADER/mach-o/loader.h
# (struct proc *)->p_proc_ro->p_platform_data.p_platform
P_PLATFORM_MACOS = 1
P_PLATFORM_IOS = 2
P_PLATFORM_TVOS = 3
P_PLATFORM_WATCHOS = 4
P_PLATFORM_BRIDGEOS = 5
P_PLATFORM_MACCATALYST = 6
P_PLATFORM_IOSSIMULATOR = 7
P_PLATFORM_TVOSSIMULATOR = 8
P_PLATFORM_WATCHOSSIMULATOR = 9
P_PLATFORM_DRIVERKIT = 10

# File: osfmk/ipc/ipc_object.h
IO_BITS_ACTIVE = 0x80000000
IO_BITS_KOTYPE = 0x3ff

# File: kern_memorystatus.h
JETSAM_PRIORITY_MAX = 210
P_MEMSTAT_FROZEN = 0x00000002


P_PLATFORM_MACOSEXCLAVEKIT = 16
P_PLATFORM_IOSEXCLAVEKIT = 18

#File: osfmk/ipc/ipc_importance.h
IIE_TYPE_BITS = 1
IIE_TYPE_MASK = ((1 << IIE_TYPE_BITS) - 1)
IIE_TYPE_TASK =     0x00000000
IIE_TYPE_INHERIT =  0x00000001

#File: osfmk/mach/mach_voucher_types.h
MACH_VOUCHER_ATTR_KEY_NONE = 0
MACH_VOUCHER_ATTR_KEY_NUM_WELL_KNOWN = 8
IV_UNUSED_KEYINDEX = ~0
MACH_VOUCHER_ATTR_KEY_ALL = ~0
MACH_VOUCHER_ATTR_KEY_NUM = 8

if __name__ == "__main__":
    pass

