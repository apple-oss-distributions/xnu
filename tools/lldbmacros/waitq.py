from xnu import *
from utils import *
from core.configuration import *

import sys
import struct

def _swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]

def _getSafeQ(queue):
    g_wqs = kern.GetGlobalVariable('global_waitqs')
    g_cnt = unsigned(kern.GetGlobalVariable('g_num_waitqs'))

    q_hash = unsigned(queue)
    q_hash >>= 4
    q_hash *= 0x5052acdb
    q_hash &= 0xffffffff
    q_hash ^= _swap32(q_hash)

    return addressof(g_wqs[q_hash & (g_cnt - 1)])

class Waitq(object):
    """
    Helper class to wrap wait queues
    """

    def __init__(self, addr):
        self._wq = kern.CreateTypedPointerFromAddress(unsigned(addr), 'struct waitq')
        self._ty = unsigned(self._wq.waitq_type) & 0x7

    def kind(self):
        return GetEnumName('waitq_type_t', self._ty, 'WQT_')

    def fifo(self):
        return self._wq.waitq_fifo

    def irq_safe(self):
        return self._ty in [
                GetEnumValue('waitq_type_t', 'WQT_QUEUE'),
                GetEnumValue('waitq_type_t', 'WQT_TURNSTILE')]

    def safe_queue(self):
        if self.irq_safe():
            return self._wq
        elif self._ty == GetEnumValue('waitq_type_t', 'WQT_PORT'):
            ts = self._wq.waitq_ts
            if ts: return ts.ts_waitq.waitq_ts
            return 0
        else:
            return _getSafeQ(self._wq)

    def bitsStr(self):
        out_str = ""

        cticket = int(self._wq.waitq_interlock.cticket)
        try:
            kern.GetGlobalVariable('has_lock_pv')
            cticket &= ~1
        except:
            pass

        if cticket != int(self._wq.waitq_interlock.nticket):
            out_str += "L"
        else:
            out_str += "-"
        if self._wq.waitq_fifo:
            out_str += 'F'
        else:
            out_str += "-"
        if self.irq_safe():
            out_str += 'I'
        else:
            out_str += "-"
        if self._wq.waitq_preposted:
            out_str += 'P'
        else:
            out_str += "-"
        return out_str

    def hasThreads(self):
        for _ in self.iterateThreads():
            return True
        return False

    def hasSets(self):
        for _ in self.iterateSets():
            return True
        return False

    def hasMembers(self):
        for _ in self.iterateMemberLinks():
            return True
        return False

    def iterateThreads(self):
        if self._ty == GetEnumValue('waitq_type_t', 'WQT_PORT'):
            ts = self._wq.waitq_ts
            if ts:
                for t in IterateSchedPriorityQueue(ts.ts_waitq.waitq_prio_queue,
                        'struct thread', 'wait_prioq_links'):
                    yield t
        elif self._ty == GetEnumValue('waitq_type_t', 'WQT_TURNSTILE'):
            for t in IterateSchedPriorityQueue(self._wq.waitq_prio_queue,
                    'struct thread', 'wait_prioq_links'):
                yield t
        elif self._ty == GetEnumValue('waitq_type_t', 'WQT_QUEUE'):
            for t in IterateCircleQueue(self._wq.waitq_queue, 'thread', 'wait_links'):
                yield t
        else:
            for t in IterateCircleQueue(_getSafeQ(self._wq).waitq_queue, 'thread', 'wait_links'):
                if t.waitq.wq_q == self._wq: yield t

    def asTurnstile(self):
        if self._ty == GetEnumValue('waitq_type_t', 'WQT_TURNSTILE'):
            return containerof(self._wq, 'turnstile', 'ts_waitq')
        return None

    def asSelinfo(self):
        if self._ty == GetEnumValue('waitq_type_t', 'WQT_SELECT'):
            return containerof(self._wq, 'selinfo', 'si_waitq')
        return None

    def asPort(self):
        if self._ty == GetEnumValue('waitq_type_t', 'WQT_PORT'):
            return containerof(self._wq, 'ipc_port', 'ip_waitq')
        return None

    def asPset(self):
        if self._ty == GetEnumValue('waitq_type_t', 'WQT_PORT_SET'):
            return containerof(self._wq, 'ipc_pset', 'ips_wqset')
        return None

    def iterateSets(self):
        if self._ty == GetEnumValue('waitq_type_t', 'WQT_PORT'):
            for link in IterateCircleQueue(self._wq.waitq_links, 'struct waitq_link', 'wql_qlink'):
                wqs = link.wql_wqs & ~1
                if wqs: yield Waitq(kern.GetValueFromAddress(wqs))

        if self._ty == GetEnumValue('waitq_type_t', 'WQT_SELECT'):
            link = self._wq.waitq_sellinks.next
            while link:
                sellink = containerof(link, 'struct waitq_sellink', 'wql_next')
                wqs = sellink.wql_wqs & ~1
                if wqs: yield Waitq(kern.GetValueFromAddress(wqs))
                link = link.next

    def iterateMembers(self):
        for l in self.iterateMemberLinks():
            yield Waitq(l.wql_wq)

    def iterateMemberLinks(self):
        if self._ty == GetEnumValue('waitq_type_t', 'WQT_PORT_SET'):
            wqs = kern.CreateTypedPointerFromAddress(unsigned(self._wq), 'struct waitq_set')
            for l in IterateCircleQueue(wqs.wqset_links, 'struct waitq_link', 'wql_slink'):
                yield l
            for l in IterateCircleQueue(wqs.wqset_preposts, 'struct waitq_link', 'wql_slink'):
                yield l

@lldb_type_summary(['waitq_t', 'waitq', 'waitq *', 'waitq_set', 'waitq_set *', 'select_set', 'select_set *'])
@header("{:<20s} {:<20s} {:<10s} {:<4s} {:>16s} {:>8s}".format(
    'waitq', 'safequeue', 'kind', 'bits', 'evtmask', 'waiters'))
def GetWaitqSummary(waitq):
    if isinstance(waitq, Waitq):
        wq = waitq
    else:
        wq = Waitq(waitq)

    threads = len([t for t in wq.iterateThreads()])

    return "{q:<#20x} {safeq:<#20x} {kind:<10s} {bits:<4s} {q.waitq_eventmask:>#16x} {threads:>8d}".format(
            q=wq._wq, safeq=wq.safe_queue(), kind=wq.kind(), bits=wq.bitsStr(), threads=threads)

# Macro: showwaitq

def ShowWaitqHelper(waitq, O=None):
    print(GetWaitqSummary(waitq))


    if waitq.hasThreads():
        print("Waiters:")
    with O.table("{:<20s} {:<20s}".format('waiter', 'event'), indent=True):
        for thread in waitq.iterateThreads():
            print("{:<#20x} {:<#20x}".format(unsigned(thread), thread.wait_event))

    if waitq.hasSets():
        print("Sets:")
    with O.table(GetWaitqSummary.header, indent=True):
        for wqs in waitq.iterateSets():
            print(GetWaitqSummary(wqs))

    if waitq.hasMembers():
        print("Members:")
    with O.table(GetWaitqSummary.header, indent=True):
        for link in waitq.iterateMemberLinks():
            print(GetWaitqSummary(link.wql_wq))

@lldb_command('showwaitq', fancy=True)
def ShowWaitq(cmd_args=None, cmd_options={}, O=None):
    """ Print waitq structure summary.

        usage: showwaitq <waitq/waitq_set>
    """

    if cmd_args is None or len(cmd_args) == 0:
        return O.error("Missing waitq argument")

    with O.table(GetWaitqSummary.header):
        ShowWaitqHelper(Waitq(kern.GetValueFromAddress(cmd_args[0], 'struct waitq *')), O)

# EndMacro: showwaitq
# Macro: showglobalwaitqs

@lldb_command('showglobalwaitqs', 'A', fancy=True)
def ShowGlobalWaitqs(cmd_args=None, cmd_options={}, O=None):
    """ Summarize global waitq usage

        usage: showglobalwaitqs [-A]
            -A  : show all queues, not only non empty ones
    """

    full = '-A' in cmd_options

    with O.table(GetWaitqSummary.header):
        for q in range(0, int(kern.globals.g_num_waitqs)):
            wq = Waitq(addressof(kern.globals.global_waitqs[q]))
            if not full and not wq.hasThreads():
                continue
            ShowWaitqHelper(wq, O)

# EndMacro: showglobalwaitqs
# Macro: showglobalqstats

@lldb_command('showglobalqstats', "OF")
def ShowGlobalQStats(cmd_args=None, cmd_options={}):
    """ Summarize global waitq statistics

        usage: showglobalqstats [-O] [-F]
            -O  : only output waitqs with outstanding waits
            -F  : output as much backtrace as was recorded
    """
    global kern
    q = 0

    if not hasattr(kern.globals, 'g_waitq_stats'):
        print("No waitq stats support (use DEVELOPMENT kernel)!")
        return

    print("Global waitq stats")
    print("{0: <18s} {1: <8s} {2: <8s} {3: <8s} {4: <8s} {5: <8s} {6: <32s}".format('waitq', '#waits', '#wakes', '#diff', '#fails', '#clears', 'backtraces'))

    waiters_only = False
    full_bt = False
    if "-O" in cmd_options:
        waiters_only = True
    if "-F" in cmd_options:
        full_bt = True

    fmt_str = "{q: <#18x} {stats.waits: <8d} {stats.wakeups: <8d} {diff: <8d} {stats.failed_wakeups: <8d} {stats.clears: <8d} {bt_str: <s}"
    while q < kern.globals.g_num_waitqs:
        waitq = kern.globals.global_waitqs[q]
        stats = kern.globals.g_waitq_stats[q]
        diff = stats.waits - stats.wakeups
        if diff == 0 and waiters_only:
            q = q + 1
            continue
        last_waitstr = ''
        last_wakestr = ''
        fw_str = ''
        if (stats.last_wait[0]):
            last_waitstr = GetSourceInformationForAddress(unsigned(stats.last_wait[0]))
        if (stats.last_wakeup[0]):
            last_wakestr = GetSourceInformationForAddress(unsigned(stats.last_wakeup[0]))
        if (stats.last_failed_wakeup[0]):
            fw_str = GetSourceInformationForAddress(unsigned(stats.last_failed_wakeup[0]))

        if full_bt:
            f = 1
            while f < kern.globals.g_nwaitq_btframes:
                if stats.last_wait[f]:
                    last_waitstr = "{0}->{1}".format(GetSourceInformationForAddress(unsigned(stats.last_wait[f])), last_waitstr)
                if stats.last_wakeup[f]:
                    last_wakestr = "{0}->{1}".format(GetSourceInformationForAddress(unsigned(stats.last_wakeup[f])), last_wakestr)
                if stats.last_failed_wakeup[f]:
                    fw_str = "{0}->{1}".format(GetSourceInformationForAddress(unsigned(stats.last_failed_wakeup[f])), fw_str)
                f = f + 1
        bt_str = ''
        if last_waitstr:
            bt_str += "wait : " + last_waitstr
        if last_wakestr:
            if bt_str:
                bt_str += "\n{0: <70s} ".format('')
            bt_str += "wake : " + last_wakestr
        if fw_str:
            if bt_str:
                bt_str += "\n{0: <70s} ".format('')
            bt_str += "fails: " + fw_str

        print(fmt_str.format(q=addressof(waitq), stats=stats, diff=diff, bt_str=bt_str))
        q = q + 1

# EndMacro: showglobalqstats
