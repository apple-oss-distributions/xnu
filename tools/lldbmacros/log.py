from collections import namedtuple
from itertools import chain

from xnu import *

LogBlock = namedtuple('LogBlock', ['blk_id', 'blk'])
LQEntry = namedtuple('LQEntry', ['state', 'size', 'lmid', 'data'])
LogStreamElem = namedtuple(
    'LogStreamElem', ['blk_id', 'offset', 'lsm', 'ftid'])


class PPrinter(object):
    """ Naive yet helpful pretty printer. """

    def __init__(self, O, kv_indent=17):
        self._O = O
        self._kv_fmt = "{:<" + str(kv_indent) + "}"

    def header(self, title, upper_case=False):
        """ Prints out a header with a given text. """
        if upper_case:
            title = title.upper()
        print(self._O.format("{VT.Bold}{:s}{VT.EndBold}", title))

    def table(self, args):
        """ Switches to a table mode. """
        return self._O.table(args)

    @staticmethod
    def print(*values):
        """ A simple wrapper around `print` providing same functionality. """
        print(*values)

    def kvprint(self, key, fmt, *values):
        """ Pretty prints aligned `key: values`. The `fmt` argument specifies
            value(s) format string.
        """
        print(self._kv_fmt.format(key), end=": ")
        print(fmt.format(*values))

    @staticmethod
    def empty_line():
        """ Prints an empty line. """
        print(" \n")


class FTID(object):
    """ Represents a firehose tracepoint identifier. Decodes the tracepoint
        and provides details on its fields.
    """

    TYPE = {
        0x00: "default",
        0x01: "info",
        0x02: "debug",
        0x10: "error",
        0x11: "fault"
    }

    def __init__(self, ftid):
        self._ftid = ftid

    @property
    def value(self):
        """ Returns a firehose tracepoint id compound value. """
        return self._ftid.ftid_value

    @property
    def namespace(self):
        """ Returns a tuple of a namespace identifier and its name. """
        ns_id = int(self._ftid.ftid._namespace)
        ns_name = GetEnumName('firehose_tracepoint_namespace_t',
                              ns_id, 'firehose_tracepoint_namespace')
        return (ns_id, ns_name.split('_')[-1])

    @property
    def code(self):
        """ Returns a tracepoint code value. """
        return int(self._ftid.ftid._code)

    @property
    def flags(self):
        """ Returns a tuple of a tracepoint flag and its name. """
        flag_id = unsigned(self._ftid.ftid._flags)
        flag_name = GetEnumName('firehose_tracepoint_flags_t',
                                flag_id, '_firehose_tracepoint_flags_')
        parts = flag_name.split('_')
        flag_name = parts[0] + ":" + " ".join(parts[2:])
        return (flag_id, flag_name)

    @property
    def type(self):
        """ Returns a tuple of a tracepoint type and its name.  """
        # GetEnumName cannot be used because _firehose_tracepoint_type_trace_t
        # is defined as OS_ENUM which defines values as anonymous enum
        # unrelated to the type name whatsoever.
        code_id = int(self._ftid.ftid._type)
        return (code_id, self.TYPE.get(code_id, "<unknown>"))


class LogBlocks(object):
    """ A base class for objects using log blocks. """
    BLOCK_SIZE = 64

    def __init__(self, buf, blk, blk_count, is_ringbuffer):
        self._buf = buf
        self._blk = blk
        self._blk_count = blk_count
        self._is_ringbuffer = is_ringbuffer

    @property
    def block_count(self):
        """ Returns a total block count. """
        return self._blk_count

    def block_size(self, block_count=1):
        """ Returns a space size occupied by a given number of blocks. """
        return self.BLOCK_SIZE * block_count

    def block_position(self, cursor):
        """ Returns a block number and a buffer offset of a log at
            a provided position (block sequence number).
        """
        blk_id = cursor % self.block_count if self.block_count > 0 else 0
        return (blk_id, self.block_size(blk_id))

    def blocks(self, head_block=0):
        """ Returns a generator of log blocks starting at a provided
            block position.
        """
        blocks = self._blocks_range(head_block, self.block_count)
        if self._is_ringbuffer:
            blocks = chain(blocks, self._blocks_range(0, head_block))
        return blocks

    def logs(self, head_block=0):
        """ Returns a generator of `LogStreamMsg` elements starting at
            a given block position.
        """
        return (self._log_stream_msg(b.blk_id) for b in self.blocks(head_block) if b.blk)

    def _blocks_range(self, s, e):
        return (LogBlock(blk_id=i, blk=self._blk[i]) for i in range(s, e))

    def _log_stream_msg(self, blk_id):
        lsm_offset = self.block_size(blk_id)
        lsm = Cast(addressof(self._buf[lsm_offset]), 'log_stream_msg_t *')
        return LogStreamElem(blk_id=blk_id,
                             offset=lsm_offset,
                             lsm=lsm,
                             ftid=FTID(addressof(lsm.lsm_ft.ft_id)))


class LogStream(LogBlocks):
    """ Represents an OSLog Stream buffer. """

    def __init__(self, log_stream):
        super().__init__(log_stream.ls_buf,
                                        log_stream.ls_blk,
                                        log_stream.ls_blk_count,
                                        True)
        self._stream = log_stream

    @property
    def address(self):
        """ Returns a log stream address. """
        return int(self._stream)

    @property
    def enabled(self):
        """ Returns true for enabled log stream, false otherwise. """
        return self._stream.ls_enabled

    @property
    def reserved(self):
        """ Returns a total number of reserved bytes. """
        return self._stream.ls_reserved

    @property
    def logged(self):
        """ Returns a number of commited bytes and an actual number
            of logged bytes.
        """
        return (self._stream.ls_commited.v,
                self._stream.ls_commited.v - self._stream.ls_commited_wraps)

    def sync_cursor(self, cursor):
        """ Aligns read cursor so it points to the actual beginning
            of a log stream.
        """
        commited, logged = self.logged
        read = cursor
        if read + self.block_count < logged:
            read = logged
            if commited >= self.block_count:
                read -= self.block_count
        return read % self.block_count


class LogStreamCache(LogBlocks):
    """ Represents an OSLog Stream Cache.
    """

    def __init__(self, log_cache):
        super().__init__(log_cache.lc_buf,
                                             log_cache.lc_blk,
                                             log_cache.lc_blk_count,
                                             False)
        self._cache = log_cache

    @property
    def address(self):
        """ Returns a log stream cache address. """
        return addressof(self._cache)

    @property
    def stream(self):
        """ Returns a log stream cached by this instance.
        """
        return LogStream(self._cache.lc_stream) if self._cache.lc_stream else None

    @property
    def stream_cursor(self):
        """ Returns a current log stream read cursor. The value is
            a block sequence of a block to read from next.
        """
        if not self.stream:
            return 0
        return self.stream.sync_cursor(self._cache.lc_stream_pos)

    @property
    def cache_cursor(self):
        """ Returns a current log cache cursor. The value is a number
            of a block to read from next.
        """
        return self._cache.lc_blk_pos


class MsgBuffer(object):
    """ Provides access to msgbuf_t ring buffer which is primarily
        a data type behind system message buffer accessible via dmesg
        CLI command.
    """
    MSG_MAGIC = 0x063061

    def __init__(self, msgbuf):
        self._msgbuf = msgbuf
        size = int(self._msgbuf.msg_size)
        self._buffer = self._msgbuf.msg_bufc.GetSBValue().GetPointeeData(0, size)

    def __eq__(self, other):
        return unsigned(self._msgbuf) == unsigned(other._msgbuf)

    def __hash__(self):
        return hash(unsigned(self._msgbuf))

    @dyn_cached_property
    def values(self, target=None):
        """ Returns a list of all log messages. """

        return list(self._values())

    def __len__(self):
        """ Returns a number of log messages in the message buffer. """
        return len(self.values)

    def __getitem__(self, i):
        """ Returns a log message at a given index. """
        return self.values[i]

    def __iter__(self):
        """ Returns an iterator object of log messages. """
        return iter(self.values)

    def _values(self):
        """ Returns a generator object of log messages. """
        chars = (c for c in (self._at(i) for i in self._range()) if c != 0)
        line = bytearray()
        for c in chars:
            line.append(c)
            if chr(c) == '\n':
                yield line.decode(errors='backslashreplace')
                line = bytearray()
        yield line.decode(errors='backslashreplace')

    def _at(self, i):
        """ Returns a character at a given index. """
        err = lldb.SBError()
        c = self._buffer.GetUnsignedInt8(err, i)
        if not err.Success():
            raise ValueError(
                "Failed to read character at offset " + str(i) + ": " + err.GetCString())
        return c

    def _range(self):
        """ Returns character indices starting at a ring buffer head. """
        start = int(self._msgbuf.msg_bufx)
        size = int(self._msgbuf.msg_size)
        return ((start + i) % size for i in range(0, size))


class LogQueue(object):
    """ Represents a kernel log queue. """

    def __init__(self, cpu, lq):
        self._cpu = cpu
        self._lq = lq

    @property
    def cpu(self):
        """ Returns a CPU number the log queue is associated with. """
        return self._cpu

    @property
    def ptr(self):
        """ Returns a pointer to enclosed log_queue_s. """
        return self._lq

    @property
    def address(self):
        """ Returns a log queue address. """
        return int(self.ptr)

    @property
    def size(self):
        """ Returns an actual total log queue size. """
        slot_size = 1 << unsigned(self._lq.lq_mem_size_order)
        return self._lq.lq_cnt_mem_active * slot_size

    @property
    def enqueued(self):
        """ Returns a generator of logs enqueued in the log queue. """
        return self._lq_entries(addressof(self._lq.lq_log_list))

    @property
    def dispatched(self):
        """ Returns a generator of logs dispatched by the log queue. """
        return self._lq_entries(addressof(self._lq.lq_dispatch_list))

    @staticmethod
    def _lq_entries(lqe_list):
        """ Returns a generator of LQEntry elements representing given single-linked list. """
        def lq_entry(lqe):
            lqe_state = GetEnumName('log_queue_entry_state_t',
                                    lqe.lqe_state, 'LOG_QUEUE_ENTRY_STATE_')
            return LQEntry(state=lqe_state, size=lqe.lqe_size, lmid=lqe.lqe_lm_id, data=lqe.lqe_payload)
        return (lq_entry(e) for e in IterateTAILQ_HEAD(lqe_list, 'lqe_link', 's') if e)

    @staticmethod
    def collect():
        """ Returns a list of all per-CPU log queues. """
        pcpu_lqs = addressof(kern.GetGlobalVariable('percpu_slot_oslog_queue'))
        pcpu_lqs_type = pcpu_lqs.GetSBValue().GetType().name
        cpus = range(0, kern.globals.zpercpu_early_count)

        def PCPUSlot(i):
            addr = unsigned(pcpu_lqs) + kern.PERCPU_BASE(i)
            return kern.GetValueFromAddress(addr, pcpu_lqs_type)

        return [LogQueue(cpu, PCPUSlot(cpu)) for cpu in cpus]


def show_log_stream_logs(pp, logs):
    """ Pretty prints logs metadata.
    """
    hdr = "{0:>5s} {1:>7s} {2:>6s} {3:>12s} {4:>16s} {5:>8s} {6:>9s} {7:>7s} {8:>8s} {9:>18s}"
    hdr_labels = (
        "BLOCK", "OFFSET", "LENGTH", "TIMESTAMP", "FTID",
        "TID", "NAMESPACE", "TYPE", "CODE", "FLAGS"
    )
    log_hdr = (
        "{log.blk_id:>5d} {log.offset:>7d} {ft.ft_length:>6d} {ts:>12d} "
        "{ftid.value:>16x} {ft.ft_thread:>8d} {ftid.namespace[1]:>9s} "
        "{ftid.type[1]:>7s} {ftid.code:>08x} {ftid.flags[1]:>18s}"
    )

    log_count = 0
    with pp.table(hdr.format(*hdr_labels)):
        for log in logs:
            pp.print(log_hdr.format(log=log, ts=log.lsm.lsm_ts,
                                    ft=log.lsm.lsm_ft, ftid=log.ftid))
            log_count += 1
    pp.print("(Shown {:d} logs)".format(log_count))


def show_log_stream_cache(pp, lsc):
    """ Pretty prints configuration details of a given log cache.
    """
    pp.header("Stream Cache")

    pp.kvprint("Address", "{:#0x}", lsc.address)
    pp.kvprint("Size", "{:>d} bytes ({:d} blocks)",
               lsc.block_size(lsc.block_count), lsc.block_count)
    pp.kvprint("Next Read Block", "{:d} (Offset: {:d})",
               *lsc.block_position(lsc.cache_cursor))


def show_log_stream(pp, ls, read_pos):
    """ Pretty prints configuration details of a given log stream.
    """
    pp.header("Stream")

    if not ls:
        pp.print("No log stream configured.")
        return

    commited, logged_bytes = ls.logged
    pp.kvprint("Address", "{:#0x}", ls.address)
    pp.kvprint("State", "{:s}", "Enabled" if ls.enabled else "Disabled")
    pp.kvprint("Size", "{:>d} bytes ({:d} blocks)",
               ls.block_size(ls.block_count), ls.block_count)
    pp.kvprint("Reserved", "{:d}", ls.reserved)
    pp.kvprint("Commited", "{:d}", commited)

    block, offset = ls.block_position(commited)
    pp.kvprint("Written", "{:d} bytes", logged_bytes)
    pp.kvprint("Next Write Block", "{:d} (Offset: {:d})", block, offset)

    block, offset = ls.block_position(read_pos)
    pp.kvprint("Read", "{:d} bytes", read_pos)
    pp.kvprint("Next Read Block", "{:d} (Offset: {:d})", block, offset)


def show_log_stream_stats(pp):
    """ Pretty prints values of log stream counters. """
    pp.header("Statistics")

    pp.kvprint("Total Count", "{:s}",
               GetSimpleCounter(kern.globals.oslog_s_total_msgcount))
    pp.kvprint("Metadata Count", "{:s}",
               GetSimpleCounter(kern.globals.oslog_s_metadata_msgcount))
    pp.kvprint("Streamed Logs", "{:s}",
               GetSimpleCounter(kern.globals.oslog_s_streamed_msgcount))
    pp.kvprint("Dropped Logs", "{:s}",
               GetSimpleCounter(kern.globals.oslog_s_dropped_msgcount))
    pp.kvprint("Invalid Logs", "{:s}",
               GetSimpleCounter(kern.globals.oslog_s_error_count))


def show_log_stream_info(show_meta, O=None):
    """ Pretty prints configuration details of OSLog Streaming and
        its current content.
    """
    pp = PPrinter(O)
    log_cache = LogStreamCache(kern.globals.log_stream_cache)

    pp.empty_line()
    pp.header("Overview", True)
    show_log_stream_stats(pp)
    show_log_stream_cache(pp, log_cache)
    show_log_stream(pp, log_cache.stream, log_cache.stream_cursor)

    if not show_meta:
        return

    pp.empty_line()
    pp.header("Cached Stream Logs", True)
    show_log_stream_logs(pp, log_cache.logs(0))

    if log_cache.stream:
        pp.empty_line()
        pp.header("Stream Logs", True)
        show_log_stream_logs(
            pp, log_cache.stream.logs(log_cache.stream_cursor))


def show_log_queues(pp, log_queues, show_logs):
    """ Pretty prints log queue summary and logs. """
    hdr = "{:>3s} {:>16s} {:>2s} {:>10s} {:>10s} {:>5s} {:>8s} {:>6s} {:>6s} {:>8s}"
    hdr_labels = (
        "CPU", "ADDRESS", "ON", "STATE", "RECONF", "SLOTS",
        "SIZE", "AVAIL", "STORED", "EN_ROUTE"
    )
    hdr_lq = (
        "{cpu:>3s} {lq.address:>16x} {lq.ptr.lq_ready:>2d} {state:>10s} {reconf:>10s} "
        "{lq.ptr.lq_cnt_mem_active:>5d} {size:>8d} {lq.ptr.lq_cnt_mem_avail:>6d} "
        "{enq:>6d} {disp:>8d}"
    )

    def show_log_queue(lq, enqueued, dispatched):
        state = GetEnumName(
            'lq_mem_state_t', lq._lq.lq_mem_state, 'LQ_MEM_STATE_')
        reconf = GetEnumName(
            'lq_req_state_t', lq._lq.lq_req_state, 'LQ_REQ_STATE_')
        cpu = "N/A" if lq.cpu is None else str(lq.cpu)
        pp.print(hdr_lq.format(lq=lq, state=state, size=lq.size, reconf=reconf, cpu=cpu,
                               enq=len(enqueued),
                               disp=len(dispatched)))

    if show_logs:
        for lq in log_queues:
            lq_enqueued = list(lq.enqueued)
            lq_dispatched = list(lq.dispatched)
            pp.empty_line()
            with pp.table(hdr.format(*hdr_labels)):
                show_log_queue(lq, lq_enqueued, lq_dispatched)

            pp.empty_line()
            pp.header("Enqueues Log Messages")
            show_log_queue_logs(pp, lq_enqueued)

            pp.empty_line()
            pp.header("Dispatched Log Messages")
            show_log_queue_logs(pp, lq_dispatched)

            pp.empty_line()
        return

    with pp.table(hdr.format(*hdr_labels)):
        for lq in log_queues:
            show_log_queue(lq, list(lq.enqueued), list(lq.dispatched))


def show_log_queue_logs(pp, lqe_list):
    """ Pretty prints log queue logs. """
    if not lqe_list:
        pp.print("No log messages present")
        return

    hdr = ("{:>5s} {:>7s} {:>10s} "
           "{:>12s} {:>8s} "
           "{:>16s} {:>9s} {:>7s} {:>8s} {:>18s}")
    hdr_labels = (
        "LM_ID", "LM_SIZE", "STATE", "TIMESTAMP", "LOG_SIZE",
        "FTID", "NAMESPACE", "TYPE", "CODE", "FLAGS"
    )
    log_hdr = (
        "{lqe.lmid:>5x} {lqe.size:>7d} {lqe.state:>10s} "
        "{d.lp_timestamp:>12d} {d.lp_data_size:>8d} "
        "{ftid.value:>16x} {ftid.namespace[1]:>9s} "
        "{ftid.type[1]:>7s} {ftid.code:>08x} {ftid.flags[1]:>18s}"
    )
    with pp.table(hdr.format(*hdr_labels)):
        for lqe in lqe_list:
            pp.print(log_hdr.format(lqe=lqe, d=lqe.data,
                                    ftid=FTID(lqe.data.lp_ftid)))
    pp.print("(Shown {:d} logs)".format(len(lqe_list)))


@lldb_command('showlogstream', 'L', fancy=True)
def showLogStream(cmd_args=None, cmd_options=None, O=None):
    """ Displays the contents of the log stream and the log stream cache.

    showlogstream [-L]

    Options:
    -L: Show metadata of logs stored in the log stream and the cache
    """

    show_meta = "-L" in cmd_options

    show_log_stream_info(show_meta, O)


@lldb_command('showlq', 'LC:A:', fancy=True)
def showLogQueue(cmd_args=None, cmd_options=None, O=None):
    """ Displays the contents of the log queue.

    usage: showlq [-C cpu_num][-A addr][-L]

        -C n    Shows a log queue summary of a selected CPU.
        -A a    Shows a log queue summary at a given address.
        -L      Show metadata of enqueued and dispatched logs

    Options -A and -C are mutually exclusive.
    If no options provided summaries of all per-CPU log queues are shown.

    Examples:
        showlq
        showlq -C 2 -L
        showlq -A 0xfffffff123456789 -L
    """

    log_queues = LogQueue.collect()

    if "-C" in cmd_options and "-A" in cmd_options:
        raise ArgumentError("Options -A and -C are mutually exclusive.")

    if "-C" in cmd_options:
        cpu_no = ArgumentStringToInt(cmd_options['-C'])
        if cpu_no not in range(0, len(log_queues)):
            print("CPU number out of [0, {:d}) range".format(len(log_queues)))
            return
        log_queues = [lq for lq in log_queues if lq.cpu == cpu_no]
    elif "-A" in cmd_options:
        addr = ArgumentStringToInt(cmd_options['-A'])
        log_queues = [lq for lq in log_queues if addr == lq.address]
        if not log_queues:
            lq = kern.GetValueFromAddress(addr, 'log_queue_t')
            log_queues = [LogQueue(None, lq)]

    show_logs = "-L" in cmd_options

    show_log_queues(PPrinter(O), log_queues, show_logs)


@lldb_command('showmsgbuf', 'C:F')
def showMsgBuf(cmd_args=None, cmd_options=None):
    """ Displays the contents of msgbuf_t type at a given address.

        usage: showmsgbuf [-C <num>][-F] addr

        -C <num>    Shows first or last (if negative) specified number of logs.
        -F          Show the content even if the magic key indicates data corruption.
    """

    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    addr = kern.GetValueFromAddress(cmd_args[0], 'struct msgbuf *')

    if addr.msg_magic != MsgBuffer.MSG_MAGIC:
        print("Error: Invalid msgbuf_t magic key {:#x} (expected {:#x}). "
              "Invalid address or the content is corrupted.".format(addr.msg_magic, MsgBuffer.MSG_MAGIC))
        if not "-F" in cmd_options:
            return

    msgbuf = MsgBuffer(addr)

    if "-C" in cmd_options:
        count = ArgumentStringToInt(cmd_options['-C'])
        n = min(abs(count), len(msgbuf))
        msgbuf = msgbuf[:n] if count > 0 else msgbuf[-n:]

    for msg in msgbuf:
        print(msg.rstrip("\n"))


@lldb_command('systemlog', 'C:F')
def systemLog(cmd_args=None, cmd_options=None):
    """ Displays the contents of the system message buffer.

        usage: systemlog [-C <num>][-F]

        -C <num>    Shows first or last (if negative) specified number of logs.
        -F          Show the content even if the magic key indicates data corruption.
    """
    showMsgBuf([unsigned(kern.globals.msgbufp)], cmd_options)
