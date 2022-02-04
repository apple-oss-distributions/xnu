""" Some of the functionality here is a copy of existing macros from memory.py
    with the VM specific stuff removed so the macros work with any btlog.
    Eventually the zstack macros should be refactored to reuse the generic btlog
    support added here.
"""

from xnu import *

@lldb_type_summary(['btlog_t *'])
@header("{0: <20s} {1: <9s} {2: <6s} {3: >9s}".format("btlog", "capacity", "depth", "count"))
def GetBTLogSummary(btlog):
    """ Summarizes btlog structure.
        params: btlog: value - value object representing a btlog in kernel
        returns: str - summary of the btlog
    """

    index = btlog.head
    records = btlog.btrecords
    record_size = btlog.btrecord_size
    count = 0

    while index != 0xffffff:
        addr = records + (index * record_size)
        record = kern.GetValueFromAddress(addr, 'btlog_record_t *')
        index = record.next
        count += 1

    capacity = (btlog.btlog_buffersize - sizeof('btlog_t')) / btlog.btrecord_size

    format_string = "{0: <#20x} {1: <9d} {2: <6d} {3: >9d}"

    return format_string.format(btlog, capacity, btlog.btrecord_btdepth, count)

def GetBTLogEntryBacktrace(depth, record):
    """ Helper routine for getting a btlog record backtrace stack.
        params:
            depth:int - The depth of the stack record
            record:btlog_record_t * - A btlog record
        returns:
            str - string with backtrace in it.
    """
    out_str = ''
    frame = 0
    if not record:
        return "no record!"

    depth_val = unsigned(depth)
    while frame < depth_val:
        frame_pc = record.bt[frame]
        if not frame_pc or int(frame_pc) == 0:
            break
        symbol_arr = kern.SymbolicateFromAddress(frame_pc)
        if symbol_arr:
            symbol_str = str(symbol_arr[0].addr)
        else:
            symbol_str = ''
        out_str += "{0: <#0x} <{1: <s}>\n".format(frame_pc, symbol_str)
        frame += 1
    return out_str

def ShowBTLogRecord(record, index, depth, count):
    """ Helper routine for printing a single btlog record
        params:
            record:btlog_record_t * -  A BTLog record
            index:int - Index for the record in the BTLog table
            depth:int - Depth of stack
            count:int - Active count
        returns:
            None
    """

    out_str = ('-' * 8)
    out_str += " OP {0: <d} Stack Index {1: <d} with active refs {2: <d} of {3: <d} {4: <s}\n".format(record.operation, index, record.ref_count, count, ('-' * 8))
    print out_str
    print GetBTLogEntryBacktrace(depth, record)
    print " \n"

# Macro: showbtlog
@lldb_command('showbtlog')
def ShowBTLogHelper(cmd_args=None):
    """ Display a summary of the specified btlog
        Usage: showbtlog <btlog address>
    """

    btlog = kern.GetValueFromAddress(cmd_args[0], 'btlog_t *')
    if not btlog:
        raise ("Unknown arguments: %r" % cmd_args)

    print GetBTLogSummary.header
    print GetBTLogSummary(btlog)

# EndMacro: showbtlog


# Macro: showbtlogrecords

@lldb_command('showbtlogrecords', 'E:')
def ShowBTLog(cmd_args=None, cmd_options={}):
    """ Print all records in the btlog from head to tail.
        Usage: showbtlogrecords <btlog addr>
    """
    if not cmd_args:
        print "Print contents of btlog. \nUsage: showbtlogrecords <btlog addr>"
        return

    if "-E" in cmd_options:

        element = kern.GetValueFromAddress(cmd_options["-E"], 'void *')
    else:
        element = None

    btlog = kern.GetValueFromAddress(cmd_args[0], 'btlog_t *')
    if not btlog:
        raise ("Unknown arguments: %r" % cmd_args)

    records = btlog.btrecords
    record_size = btlog.btrecord_size
    depth = btlog.btrecord_btdepth
    count = btlog.active_element_count;

    if not element:

        index = btlog.head
        while index != 0xffffff:
            addr = records + (index * record_size)
            record = kern.GetValueFromAddress(addr, 'btlog_record_t *')
            ShowBTLogRecord(record, index, depth, count)
            index = record.next

    else:

        if btlog.caller_will_remove_entries_for_element == 1:
            print "'-E' not supported with this type of btlog"
            return

        if (element >> 32) != 0:
            element = element ^ 0xFFFFFFFFFFFFFFFF
        else:
            element = element ^ 0xFFFFFFFF

        scan_items = 0
        hashelem = cast(btlog.elem_linkage_un.element_hash_queue.tqh_first,
            'btlog_element_t *')
        while hashelem != 0:

            if unsigned(hashelem.elem) == element:
                recindex = hashelem.recindex
                recoffset = recindex * record_size
                record = kern.GetValueFromAddress(records + recoffset,
                    'btlog_record_t *')
                ShowBTLogRecord(record, recindex, depth, count)
                scan_items = 0

            hashelem = cast(hashelem.element_hash_link.tqe_next, 'btlog_element_t *')
            scan_items += 1
            if scan_items % 100 == 0:
               print "Scanning is ongoing. {0: <d} items scanned since last check." \
                  .format(scan_items)

# EndMacro : showbtlogrecords
