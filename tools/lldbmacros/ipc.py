""" Please make sure you read the README file COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file. 
"""
from __future__ import absolute_import, division, print_function

from builtins import hex
from builtins import range

import sys
from xnu import *
from utils import *
from process import *
from bank import *
from waitq import *
from ioreg import *
from memory import *
import xnudefines
import kmemory

@lldb_type_summary(['struct ipc_entry_table *', 'ipc_entry_table_t'])
def PrintIpcEntryTable(array):
    t, s = kalloc_array_decode(array, 'struct ipc_entry')
    return "ptr = {:#x}, size = {:d}, elem_type = struct ipc_entry".format(unsigned(t), s)

@lldb_type_summary(['struct ipc_port_requests_table *', 'ipc_port_requests_table_t'])
def PrintIpcPortRequestTable(array):
    t, s = kalloc_array_decode(array, 'struct ipc_port_requests')
    return "ptr = {:#x}, size = {:d}, elem_type = struct ipc_port_requests".format(unsigned(t), s)

def GetSpaceTable(space):
    """ Return the tuple of (entries, size) of the table for a space
    """
    table = space.is_table.__smr_ptr
    if table:
        return kalloc_array_decode(table, 'struct ipc_entry')
    return (None, 0)

def GetSpaceEntriesWithBits(is_tableval, num_entries, mask):
    base = is_tableval.GetSBValue().Dereference()
    return (
        (index, iep)
        for index, iep in enumerate(base.xIterSiblings(1, num_entries), 1)
        if  iep.xGetIntegerByName('ie_bits') & mask
    )

def GetSpaceObjectsWithBits(is_tableval, num_entries, mask, ty):
    base = is_tableval.GetSBValue().Dereference()
    return (
        iep.xCreateValueFromAddress(
            None,
            iep.xGetIntegerByName('ie_object'),
            ty,
        )
        for iep in base.xIterSiblings(1, num_entries)
        if  iep.xGetIntegerByName('ie_bits') & mask
    )


@header("{0: <20s} {1: <6s} {2: <6s} {3: <10s} {4: <32s}".format("task", "pid", '#acts', "tablesize", "command"))
def GetTaskIPCSummary(task, show_busy = False):
    """ Display a task's ipc summary. 
        params:
            task : core.value represeting a Task in kernel
        returns
            str - string of ipc info for the task
    """
    out_string = ''
    format_string = "{0: <#20x} {1: <6d} {2: <6d} {3: <10d} {4: <32s}"
    busy_format = " {0: <10d} {1: <6d}"
    proc_name = ''
    if not task.active:
        proc_name = 'terminated: '
    if task.halting:
        proc_name += 'halting: '
    proc_name += GetProcNameForTask(task)
    _, table_size = GetSpaceTable(task.itk_space)
    out_string += format_string.format(task, GetProcPIDForTask(task), task.thread_count, table_size, proc_name)
    if show_busy:
        nbusy, nmsgs = GetTaskBusyPortsSummary(task)
        out_string += busy_format.format(nbusy, nmsgs)
        return (out_string, table_size, nbusy, nmsgs)
    return (out_string, table_size)

@header("{0: <20s} {1: <6s} {2: <6s} {3: <10s} {4: <32s} {5: <10s} {6: <6s}".format("task", "pid", '#acts', "tablesize", "command", "#busyports", "#kmsgs"))
def GetTaskBusyIPCSummary(task):
    return GetTaskIPCSummary(task, True)

def GetTaskBusyPortsSummary(task):
    is_tableval, num_entries = GetSpaceTable(task.itk_space)
    port_ty = gettype('struct ipc_port')
    nbusy = 0
    nmsgs = 0

    if is_tableval:
        ports = GetSpaceObjectsWithBits(is_tableval, num_entries, 0x00020000,
            gettype('struct ipc_port'))

        for port in ports:
            if not port or port == xnudefines.MACH_PORT_DEAD:
                continue
            count = port.xGetIntegerByPath('.ip_messages.imq_msgcount')
            if count:
                nbusy += 1
                nmsgs += count

    return (nbusy, nmsgs)


@header("{:<20s} {:<20s} {:<10s} {:>6s}  {:<20s}  {:>8s}  {:<20s} {:s}".format(
            "port", "waitqueue", "recvname", "refs", "receiver", "nmsgs", "service", "dest/kobject"))
def PrintPortSummary(port, show_kmsg_summary=True, show_sets=False, prefix="", O=None):
    """ Display a port's summary
        params:
            port : core.value representing a port in the kernel
        returns
            str  : string of ipc info for the given port
    """

    format_string = "{:<#20x} {:<#20x} {:#010x} {:>6d}  {:<#20x}  {:>8d}  {:<20s} {:<s}"
    ip_messages = port.ip_messages
    receiver_name = ip_messages.imq_receiver_name
    splabel_name = 'N/A'
    space = 0
    refs = 0
    ip_object = port.ip_object
    if ip_object.io_bits & 0x80000000:
        if receiver_name:
            space = unsigned(port.ip_receiver)

        try:
            if port.ip_service_port:
                splabel = Cast(port.ip_splabel, 'struct ipc_service_port_label *')
                splabel_name = str(splabel.ispl_service_name) # Not on RELEASE kernel
        except:
            splabel_name = 'unknown'

        dest_str = GetPortDestProc(port)[1]
    else:
        dest_str = "inactive-port"

    ip_waitq = port.ip_waitq
    print(prefix + format_string.format(unsigned(port), addressof(ip_waitq),
        unsigned(receiver_name), ip_object.io_references, space,
        ip_messages.imq_msgcount, splabel_name, dest_str))

    if show_kmsg_summary:
        with O.table(prefix + GetKMsgSummary.header):
            for kmsgp in IterateCircleQueue(ip_messages.imq_messages, 'ipc_kmsg', 'ikm_link'):
                print(prefix + GetKMsgSummary(kmsgp, prefix))

    wq = Waitq(addressof(ip_waitq))
    if show_sets and wq.hasSets():
        def doit(wq):
            for wqs in wq.iterateSets():
                PrintPortSetSummary(wqs.asPset(), space=port.ip_receiver, verbose=False, O=O)

        if O is None:
            print(PrintPortSetSummary.header)
            doit(wq)
        else:
            with O.table(PrintPortSetSummary.header, indent=True):
                doit(wq)
                print("")

def GetPortDispositionString(disp):
    if disp < 0: ## use negative numbers for request ports
        portname = 'notify'
        if disp == -1:
            disp_str = 'reqNS'
        elif disp == -2:
            disp_str = 'reqPD'
        elif disp == -3:
            disp_str = 'reqSPa'
        elif disp == -4:
            disp_str = 'reqSPr'
        elif disp == -5:
            disp_str = 'reqSPra'
        else:
            disp_str = '-X'
    ## These dispositions should match those found in osfmk/mach/message.h
    elif disp == 16:
        disp_str = 'R'  ## receive
    elif disp == 24:
        disp_str = 'dR' ## dispose receive
    elif disp == 17:
        disp_str = 'S'  ## (move) send
    elif disp == 19:
        disp_str = 'cS' ## copy send
    elif disp == 20:
        disp_str = 'mS' ## make send
    elif disp == 25:
        disp_str = 'dS' ## dispose send
    elif disp == 18:
        disp_str = 'O'  ## send-once
    elif disp == 21:
        disp_str = 'mO' ## make send-once
    elif disp == 26:
        disp_str = 'dO' ## dispose send-once
    ## faux dispositions used to string-ify IPC entry types
    elif disp == 100:
        disp_str = 'PS' ## port set
    elif disp == 101:
        disp_str = 'dead' ## dead name
    elif disp == 102:
        disp_str = 'L' ## LABELH
    elif disp == 103:
        disp_str = 'V' ## Thread voucher (thread->ith_voucher->iv_port)
    ## Catch-all
    else:
        disp_str = 'X'  ## invalid
    return disp_str

def GetPortPDRequest(port):
    """ Returns the port-destroyed notification port if any
    """
    if port.ip_has_watchport:
        return port.ip_twe.twe_pdrequest
    if not port.ip_specialreply:
        return port.ip_pdrequest
    return 0

def GetKmsgHeader(kmsgp):
    """ Helper to get mach message header of a kmsg.
        Assumes the kmsg has not been put to user.
    params:
        kmsgp : core.value representing the given ipc_kmsg_t struct
    returns:
        Mach message header for kmsgp
    """
    if kmsgp.ikm_type == GetEnumValue('ipc_kmsg_type_t', 'IKM_TYPE_ALL_INLINED'):
        return kern.GetValueFromAddress(int(addressof(kmsgp.ikm_big_data)), 'mach_msg_header_t *')
    if kmsgp.ikm_type == GetEnumValue('ipc_kmsg_type_t', 'IKM_TYPE_UDATA_OOL'):
        return kern.GetValueFromAddress(int(addressof(kmsgp.ikm_small_data)), 'mach_msg_header_t *')
    return kern.GetValueFromAddress(unsigned(kmsgp.ikm_kdata), 'mach_msg_header_t *')

@header("{:<20s} {:<20s} {:<20s} {:<10s} {:>6s}  {:<20s}  {:<8s}  {:<26s} {:<26s}".format(
            "", "kmsg", "header", "msgid", "size", "reply-port", "disp", "source", "destination"))
def GetKMsgSummary(kmsgp, prefix_str=""):
    """ Display a summary for type ipc_kmsg_t
        params:
            kmsgp : core.value representing the given ipc_kmsg_t struct
        returns:
            str   : string of summary info for the given ipc_kmsg_t instance
    """
    kmsghp = GetKmsgHeader(kmsgp)
    kmsgh = dereference(kmsghp)
    out_string = ""
    out_string += "{:<20s} {:<#20x} {:<#20x} {kmsgh.msgh_id:#010x} {kmsgh.msgh_size:>6d}  {kmsgh.msgh_local_port:<#20x}  ".format(
            '', unsigned(kmsgp), unsigned(kmsghp), kmsgh=kmsghp)
    prefix_str = "{:<20s} ".format(' ') + prefix_str
    disposition = ""
    bits = kmsgh.msgh_bits & 0xff

    # remote port
    if bits == 17:
        disposition = "rS"
    elif bits == 18:
        disposition = "rO"
    else :
        disposition = "rX" # invalid

    out_string += "{:<2s}".format(disposition)

    # local port
    disposition = ""
    bits = (kmsgh.msgh_bits & 0xff00) >> 8

    if bits == 17:
        disposition = "lS"
    elif bits == 18:
        disposition = "lO"
    elif bits == 0:
        disposition = "l-"
    else:
        disposition = "lX"  # invalid

    out_string += "{:<2s}".format(disposition)

    # voucher
    disposition = ""
    bits = (kmsgh.msgh_bits & 0xff0000) >> 16

    if bits == 17:
        disposition = "vS"
    elif bits == 0:
        disposition = "v-"
    else:
        disposition = "vX"

    out_string += "{:<2s}".format(disposition)

    # complex message
    if kmsgh.msgh_bits & 0x80000000:
        out_string += "{0: <1s}".format("c")
    else:
        out_string += "{0: <1s}".format("s")

    # importance boost
    if kmsgh.msgh_bits & 0x20000000:
        out_string += "{0: <1s}".format("I")
    else:
        out_string += "{0: <1s}".format("-")

    dest_proc_name = ""
    if GetKmsgHeader(kmsgp).msgh_remote_port:
        dest_proc_name = GetPortDestinationSummary(GetKmsgHeader(kmsgp).msgh_remote_port)

    out_string += "  {:<26s} {:<26s}\n".format(GetKMsgSrc(kmsgp), dest_proc_name)

    if kmsgh.msgh_bits & 0x80000000:
        out_string += prefix_str + "\t" + GetKMsgComplexBodyDesc.header + "\n"
        out_string += prefix_str + "\t" + GetKMsgComplexBodyDesc(kmsgp, prefix_str + "\t") + "\n"

    return out_string

@header("{: <20s} {: <20s} {: <10s}".format("descriptor", "address", "size"))
def GetMachMsgOOLDescriptorSummary(desc):
    """ Returns description for mach_msg_ool_descriptor_t * object
    """
    format_string = "{: <#20x} {: <#20x} {:#010x}"
    out_string = format_string.format(desc, desc.address, desc.size)
    return out_string


def GetKmsgDescriptors(kmsgp):
    """ Get a list of descriptors in a complex message
    """
    kmsghp = GetKmsgHeader(kmsgp)
    kmsgh = dereference(kmsghp)
    if not (kmsgh.msgh_bits & 0x80000000): # pragma pylint: disable=superfluous-parens
        return []
    ## Something in the python/lldb types is not getting alignment correct here.
    ## I'm grabbing a pointer to the body manually, and using tribal knowledge
    ## of the location of the descriptor count to get this correct
    body = Cast(addressof(Cast(addressof(kmsgh), 'char *')[sizeof(kmsgh)]), 'mach_msg_body_t *')
    #dsc_count = body.msgh_descriptor_count
    dsc_count = dereference(Cast(body, 'uint32_t *'))
    #dschead = Cast(addressof(body[1]), 'mach_msg_descriptor_t *')
    dschead = Cast(addressof(Cast(addressof(body[0]), 'char *')[sizeof('uint32_t')]), 'mach_msg_descriptor_t *')
    dsc_list = []
    for i in range(dsc_count):
        dsc_list.append(dschead[i])
    return (body, dschead, dsc_list)

def GetKmsgTotalDescSize(kmsgp):
    """ Helper to get total descriptor size of a kmsg.
        Assumes the kmsg has full kernel representation (header and descriptors)
    params:
        kmsgp : core.value representing the given ipc_kmsg_t struct
    returns:
        Total descriptor size
    """
    kmsghp = GetKmsgHeader(kmsgp)
    kmsgh = dereference(kmsghp)
    dsc_count = 0

    if kmsgh.msgh_bits & 0x80000000: # MACH_MSGH_BITS_COMPLEX
        (body, _, _) = GetKmsgDescriptors(kmsgp)
        dsc_count = dereference(Cast(body, 'uint32_t *'))

    return dsc_count * sizeof('mach_msg_descriptor_t')

@header("{: <20s} {: <8s} {: <20s} {: <10s} {: <20s}".format("kmsgheader", "size", "body", "ds_count", "dsc_head"))
def GetKMsgComplexBodyDesc(kmsgp, prefix_str=""):
    """ Routine that prints a complex kmsg's body
    """
    kmsghp = GetKmsgHeader(kmsgp)
    kmsgh = dereference(kmsghp)
    if not (kmsgh.msgh_bits & 0x80000000):  # pragma pylint: disable=superfluous-parens
        return ""
    format_string = "{: <#20x} {: <#8x} {: <#20x} {:#010x} {: <#20x}"
    out_string = ""

    (body, dschead, dsc_list) = GetKmsgDescriptors(kmsgp)
    out_string += format_string.format(kmsghp, sizeof(dereference(kmsghp)), body, len(dsc_list), dschead)
    for dsc in dsc_list:
        try:
            dsc_type = unsigned(dsc.type.type)
            out_string += "\n" + prefix_str + "Descriptor: " + xnudefines.mach_msg_type_descriptor_strings[dsc_type]
            if dsc_type == 0:
                # its a port.
                p = dsc.port.name
                dstr = GetPortDispositionString(dsc.port.disposition)
                out_string += " disp:{:s}, name:{: <#20x}".format(dstr, p)
            elif unsigned(dsc.type.type) in (1,3):
                # its OOL DESCRIPTOR or OOL VOLATILE DESCRIPTOR
                ool = dsc.out_of_line
                out_string += " " + GetMachMsgOOLDescriptorSummary(addressof(ool))
        except:
            out_string += "\n" + prefix_str + "Invalid Descriptor: {}".format(dsc)
    return out_string

def GetKmsgTrailer(kmsgp):
    """ Helper to get trailer address of a kmsg
    params:
        kmsgp : core.value representing the given ipc_kmsg_t struct
    returns:
        Trailer address
    """
    kmsghp = GetKmsgHeader(kmsgp)
    kmsgh = dereference(kmsghp)

    if (kmsgp.ikm_type == int(GetEnumValue('ipc_kmsg_type_t', 'IKM_TYPE_ALL_INLINED')) or
        kmsgp.ikm_type == int(GetEnumValue('ipc_kmsg_type_t', 'IKM_TYPE_KDATA_OOL'))):
        return kern.GetValueFromAddress(unsigned(kmsghp) + kmsgh.msgh_size, 'mach_msg_max_trailer_t *')
    else:
        if kmsgh.msgh_bits & 0x80000000: # MACH_MSGH_BITS_COMPLEX
            content_size = kmsgh.msgh_size - sizeof('mach_msg_base_t') - GetKmsgTotalDescSize(kmsgp)
        else:
            content_size = kmsgh.msgh_size - sizeof('mach_msg_header_t')
        return kern.GetValueFromAddress(unsigned(kmsgp.ikm_udata) + content_size, 'mach_msg_max_trailer_t *')

def GetKMsgSrc(kmsgp):
    """ Routine that prints a kmsg's source process and pid details
        params:
            kmsgp : core.value representing the given ipc_kmsg_t struct
        returns:
            str  : string containing the name and pid of the kmsg's source proc
    """
    trailer = GetKmsgTrailer(kmsgp)
    kmsgpid = Cast(trailer, 'uint *')[10] # audit_token.val[5]
    return "{0:s} ({1:d})".format(GetProcNameForPid(kmsgpid), kmsgpid)

@header("{:<20s} {:<20s} {:<10s} {:>6s}  {:<6s}".format(
            "portset", "waitqueue", "name", "refs", "flags"))
def PrintPortSetSummary(pset, space=0, verbose=True, O=None):
    """ Display summary for a given struct ipc_pset *
        params:
            pset : core.value representing a pset in the kernel
        returns:
            str  : string of summary information for the given pset
    """
    show_kmsg_summary = False
    if config['verbosity'] > vHUMAN :
        show_kmsg_summary = True

    ips_wqset = pset.ips_wqset
    wqs = Waitq(addressof(ips_wqset))

    local_name = unsigned(ips_wqset.wqset_index) << 8
    dest = "-"
    if space:
        is_tableval, _ = GetSpaceTable(space)
        if is_tableval:
            entry_val = GetObjectAtIndexFromArray(is_tableval, local_name >> 8)
            local_name |= unsigned(entry_val.ie_bits) >> 24
        dest = GetSpaceProcDesc(space)
    else:
        for wq in wqs.iterateMembers():
            dest = GetSpaceProcDesc(wq.asPort().ip_receiver)

    ips_object = pset.ips_object
    if ips_object.io_bits & 0x80000000:
        state = "ASet"
    else:
        state = "DSet"

    print("{:<#20x} {:<#20x} {:#010x} {:>6d}  {:<6s}  {:<20s}".format(
        unsigned(pset), addressof(ips_wqset), local_name,
        ips_object.io_references, "ASet", dest))

    if verbose and wqs.hasThreads():
        with O.table("{:<20s} {:<20s}".format('waiter', 'event'), indent=True):
            for thread in wqs.iterateThreads():
                print("{:<#20x} {:<#20x}".format(unsigned(thread), thread.wait_event))
            print("")

    if verbose and wqs.hasMembers():
        with O.table(PrintPortSummary.header, indent=True):
            for wq in wqs.iterateMembers():
                PrintPortSummary(wq.asPort(), show_kmsg_summary=show_kmsg_summary, O=O)
            print("")



# Macro: showipc

@lldb_command('showipc')
def ShowIPC(cmd_args=None):
    """  Routine to print data for the given IPC space 
         Usage: showipc <address of ipc space>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")

    ipc = kern.GetValueFromAddress(cmd_args[0], 'ipc_space *')
    if not ipc:
        print("unknown arguments:", str(cmd_args))
        return False
    print(PrintIPCInformation.header)
    PrintIPCInformation(ipc, False, False)
    return True

# EndMacro: showipc

# Macro: showtaskipc

@lldb_command('showtaskipc')
def ShowTaskIPC(cmd_args=None):
    """  Routine to print IPC summary of given task
         Usage: showtaskipc <address of task>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")

    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        print("unknown arguments:", str(cmd_args))
        return False
    print(GetTaskSummary.header + " " + GetProcSummary.header)
    pval = GetProcFromTask(tval)
    print(GetTaskSummary(tval) + " " + GetProcSummary(pval))
    print(GetTaskBusyIPCSummary.header)
    summary, _, _, _ = GetTaskBusyIPCSummary(tval)
    print(summary)
    return True

# EndMacro: showtaskipc

# Macro: showallipc

@lldb_command('showallipc')
def ShowAllIPC(cmd_args=None):
    """  Routine to print IPC summary of all tasks
         Usage: showallipc
    """
    for t in kern.tasks:
        print(GetTaskSummary.header + " " + GetProcSummary.header)
        pval = GetProcFromTask(t)
        print(GetTaskSummary(t) + " " + GetProcSummary(pval))
        print(PrintIPCInformation.header)
        PrintIPCInformation(t.itk_space, False, False)
        print("\n\n")

# EndMacro: showallipc

@lldb_command('showipcsummary', fancy=True)
def ShowIPCSummary(cmd_args=None, cmd_options={}, O=None):
    """ Summarizes the IPC state of all tasks. 
        This is a convenient way to dump some basic clues about IPC messaging. You can use the output to determine
        tasks that are candidates for further investigation.
    """
    with O.table(GetTaskIPCSummary.header):
        ipc_table_size = 0

        l = [ GetTaskIPCSummary(t) for t in kern.tasks ]
        l.sort(key = lambda e: e[1], reverse=True)

        for e in l:
            print(e[0])
            ipc_table_size += e[1]

        for t in kern.terminated_tasks:
            ipc_table_size += GetTaskIPCSummary(t)[1]

        print("Total Table size: {:d}".format(ipc_table_size))

def GetKObjectFromPort(portval):
    """ Get Kobject description from the port.
        params: portval - core.value representation of 'ipc_port *' object
        returns: str - string of kobject information
    """
    if not portval or portval == xnudefines.MACH_PORT_DEAD:
        return "MACH_PORT_DEAD"
    io_bits       = unsigned(portval.ip_object.io_bits)
    objtype_index = io_bits & 0x3ff

    if not objtype_index:
        return "not a kobject"

    kobject_addr  = kern.StripKernelPAC(unsigned(portval.ip_kobject))
    objtype_str   = GetEnumName('ipc_kotype_t', objtype_index, "IKOT_")

    desc_str = "{:<#20x} {:<16s}".format(kobject_addr, objtype_str)

    if not kobject_addr:
        pass

    elif objtype_str == 'IOKIT_OBJECT':
        iokit_classnm = GetObjectTypeStr(portval.ip_kobject)
        if not iokit_classnm:
            desc_str += " <unknown class>"
        else:
            desc_str += re.sub(r'vtable for ', r' ', iokit_classnm)

    elif objtype_str[:5] == 'TASK_' and objtype_str != 'TASK_ID_TOKEN':
        task = value(portval.GetSBValue().xCreateValueFromAddress(
            None, kobject_addr, gettype('struct task')).AddressOf())
        if GetProcFromTask(task) is not None:
            desc_str += " {:s}({:d})".format(GetProcNameForTask(task), GetProcPIDForTask(task))

    return desc_str

def GetSpaceProcDesc(space):
    """ Display the name and pid of a space's task
        params:
            space: core.value representing a pointer to a space
        returns:
            str  : string containing receiver's name and pid
    """
    task = space.is_task
    if GetProcFromTask(task) is None:
        return "task {:<#20x}".format(unsigned(task))
    return "{:s}({:d})".format(GetProcNameForTask(task), GetProcPIDForTask(task))

def GetPortDestProc(port):
    """ Display the name and pid of a given port's receiver
        params:
            port : core.value representing a pointer to a port in the kernel
        returns:
            str  : string containing receiver's name and pid
    """

    bits = unsigned(port.ip_object.io_bits) # osfmk/ipc/ipc_object.h
    name = unsigned(port.ip_messages.imq_receiver_name)

    port_is_kobject_port = bits & xnudefines.IO_BITS_KOTYPE

    if bits & xnudefines.IO_BITS_ACTIVE == 0:
        if port_is_kobject_port:
            return ('', 'inactive-kobject-port')

        return ('', 'inactive-port')

    if port_is_kobject_port:
        return ('', GetKObjectFromPort(port))

    if name == 0:
        return ('{:<#20x}'.format(port.ip_destination), 'in-transit')

    return ('{:<#20x}'.format(name), GetSpaceProcDesc(port.ip_receiver))

@header("{:<20s} {:<20s}".format("destname", "destination") )
def GetPortDestinationSummary(port):
    """ Get destination information for a port. 
        params: port - core.value representation of 'ipc_port *' object
        returns: str - string of info about ports destination
    """
    if not port or port == xnudefines.MACH_PORT_DEAD:
        return "MACH_PORT_DEAD"
    a, b = GetPortDestProc(port)
    return "{:<20s} {:<20s}".format(a, b)

@lldb_type_summary(['ipc_entry_t'])
@header("{: <20s} {: <12s} {: <8s} {: <8s} {: <8s} {: <8s} {: <20s} {: <20s}".format("object", "name", "rite", "urefs", "nsets", "nmsgs", "destname", "destination"))
def GetIPCEntrySummary(entry, ipc_name='', rights_filter=0):
    """ Get summary of a ipc entry.
        params:
            entry - core.value representing ipc_entry_t in the kernel
            ipc_name - str of format '0x0123' for display in summary.
        returns:
            str - string of ipc entry related information

        types of rights:
            'Dead'  : Dead name
            'Set'   : Port set
            'S'     : Send right
            'R'     : Receive right
            'O'     : Send-once right
            'm'     : Immovable send port
            'i'     : Immovable receive port
            'g'     : No grant port
        types of notifications:
            'd'     : Dead-Name notification requested
            's'     : Send-Possible notification armed
            'r'     : Send-Possible notification requested
            'n'     : No-Senders notification requested
            'x'     : Port-destroy notification requested
    """
    out_str = ''
    entry_ptr = int(hex(entry), 16)
    format_string = "{: <#20x} {: <12s} {: <8s} {: <8d} {: <8d} {: <8d} {: <20s} {: <20s}"
    right_str = ''
    destname_str = ''
    destination_str = ''

    ie_object = entry.ie_object
    ie_bits = int(entry.ie_bits)
    io_bits = int(ie_object.io_bits) if ie_object else 0
    urefs = int(ie_bits & 0xffff)
    nsets = 0
    nmsgs = 0
    if ie_bits & 0x00100000 :
        right_str = 'Dead'
    elif ie_bits & 0x00080000:
        right_str = 'Set'
        psetval = kern.CreateTypedPointerFromAddress(unsigned(ie_object), 'struct ipc_pset')
        wqs = Waitq(addressof(psetval.ips_wqset))
        members = 0
        for m in wqs.iterateMembers(): members += 1
        destname_str = "{:d} Members".format(members)
    else:
        if ie_bits & 0x00010000:
            if ie_bits & 0x00020000:
                # SEND + RECV
                right_str = 'SR'
            else:
                # SEND only
                right_str = 'S'
        elif ie_bits & 0x00020000:
            # RECV only
            right_str = 'R'
        elif ie_bits & 0x00040000:
            # SEND_ONCE
            right_str = 'O'
        portval = kern.CreateTypedPointerFromAddress(unsigned(ie_object), 'struct ipc_port')
        if int(entry.ie_request) != 0:
            requestsval, _ = kalloc_array_decode(portval.ip_requests, 'struct ipc_port_request')
            sorightval = requestsval[int(entry.ie_request)].ipr_soright
            soright_ptr = unsigned(sorightval)
            if soright_ptr != 0:
                # dead-name notification requested
                right_str += 'd'
                # send-possible armed
                if soright_ptr & 0x1:
                    right_str +='s'
                # send-possible requested
                if soright_ptr & 0x2:
                    right_str +='r'
        # No-senders notification requested
        if portval.ip_nsrequest != 0:
            right_str += 'n'
        # port-destroy notification requested
        if GetPortPDRequest(portval):
            right_str += 'x'
        # Immovable receive rights
        if portval.ip_immovable_receive != 0:
            right_str += 'i'
        # Immovable send rights
        if portval.ip_immovable_send != 0:
            right_str += 'm'
        # No-grant Port
        if portval.ip_no_grant != 0:
            right_str += 'g'
        # Port with SB filtering on
        if io_bits & 0x00001000 != 0:
            right_str += 'f'

        # early-out if the rights-filter doesn't match
        if rights_filter != 0 and rights_filter != right_str:
            return ''

        # now show the port destination part
        destname_str = GetPortDestinationSummary(portval)
        # Get the number of sets to which this port belongs
        nsets = len([s for s in Waitq(addressof(portval.ip_waitq)).iterateSets()])
        nmsgs = portval.ip_messages.imq_msgcount

    # append the generation to the name value
    # (from osfmk/ipc/ipc_entry.h)
    # bits    rollover period
    # 0 0     64
    # 0 1     48
    # 1 0     32
    # 1 1     16
    ie_gen_roll = { 0:'.64', 1:'.48', 2:'.32', 3:'.16' }
    ipc_name = '{:s}{:s}'.format(ipc_name.strip(), ie_gen_roll[(ie_bits & 0x00c00000) >> 22])

    if rights_filter == 0 or rights_filter == right_str:
        out_str = format_string.format(ie_object, ipc_name, right_str, urefs, nsets, nmsgs, destname_str, destination_str)
    return out_str

@header("{0: >20s}".format("user bt") )
def GetPortUserStack(port, task):
    """ Get UserStack information for the given port & task. 
        params: port - core.value representation of 'ipc_port *' object
                task - value representing 'task *' object
        returns: str - string information on port's userstack
    """
    out_str = ''
    if not port or port == xnudefines.MACH_PORT_DEAD:
        return out_str
    pid = port.ip_made_pid
    proc_val = GetProcFromTask(task)
    if port.ip_made_bt:
        btlib = kmemory.BTLibrary.get_shared()
        out_str += "\n".join(btlib.get_stack(port.ip_made_bt).symbolicated_frames()) + "\n"
        if pid != GetProcPID(proc_val):
            out_str += " ({:<10d})\n".format(pid)
    return out_str

@lldb_type_summary(['ipc_space *'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: <8s} {4: <10s} {5: >8s} {6: <8s}".format('ipc_space', 'is_task', 'is_table', 'flags', 'ports', 'low_mod', 'high_mod'))
def PrintIPCInformation(space, show_entries=False, show_userstack=False, rights_filter=0):
    """ Provide a summary of the ipc space
    """
    out_str = ''
    format_string = "{0: <#20x} {1: <#20x} {2: <#20x} {3: <8s} {4: <10d} {5: >8d} {6: <8d}"
    is_tableval, num_entries = GetSpaceTable(space)
    flags =''
    if is_tableval:
        flags += 'A'
    else:
        flags += ' '
    if (space.is_grower) != 0:
        flags += 'G'
    print(format_string.format(space, space.is_task, is_tableval if is_tableval else 0, flags,
            num_entries, space.is_low_mod, space.is_high_mod))

    #should show the each individual entries if asked.
    if show_entries and is_tableval:
        print("\t" + GetIPCEntrySummary.header)

        entries = (
            (index, value(iep.AddressOf()))
            for index, iep
            in  GetSpaceEntriesWithBits(is_tableval, num_entries, 0x001f0000)
        )

        for index, entryval in entries:
            entry_ie_bits = unsigned(entryval.ie_bits)
            entry_name = "{0: <#20x}".format( (index <<8 | entry_ie_bits >> 24) )
            entry_str = GetIPCEntrySummary(entryval, entry_name, rights_filter)
            if not entry_str:
                continue

            print("\t" + entry_str)
            if show_userstack:
                entryport = Cast(entryval.ie_object, 'ipc_port *')
                if entryval.ie_object and (int(entry_ie_bits) & 0x00070000) and entryport.ip_made_bt:
                    print(GetPortUserStack.header + GetPortUserStack(entryport, space.is_task))

    #done with showing entries
    return out_str

# Macro: showrights

@lldb_command('showrights', 'R:')
def ShowRights(cmd_args=None, cmd_options={}):
    """  Routine to print rights information for the given IPC space 
         Usage: showrights [-R rights_type] <address of ipc space>
                -R rights_type  : only display rights matching the string 'rights_type'

                types of rights:
                    'Dead'  : Dead name
                    'Set'   : Port set
                    'S'     : Send right
                    'R'     : Receive right
                    'O'     : Send-once right
                types of notifications:
                    'd'     : Dead-Name notification requested
                    's'     : Send-Possible notification armed
                    'r'     : Send-Possible notification requested
                    'n'     : No-Senders notification requested
                    'x'     : Port-destroy notification requested
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")

    ipc = kern.GetValueFromAddress(cmd_args[0], 'ipc_space *')
    if not ipc:
        print("unknown arguments:", str(cmd_args))
        return False
    rights_type = 0
    if "-R" in cmd_options:
        rights_type = cmd_options["-R"]
    print(PrintIPCInformation.header)
    PrintIPCInformation(ipc, True, False, rights_type)

# EndMacro: showrights

@lldb_command('showtaskrights','R:')
def ShowTaskRights(cmd_args=None, cmd_options={}):
    """ Routine to ipc rights information for a task
        Usage: showtaskrights [-R rights_type] <task address>
               -R rights_type  : only display rights matching the string 'rights_type'

               types of rights:
                   'Dead'  : Dead name
                   'Set'   : Port set
                   'S'     : Send right
                   'R'     : Receive right
                   'O'     : Send-once right
                   'm'     : Immovable send port
                   'i'     : Immovable receive port
                   'g'     : No grant port
                   'f'     : Port with SB filtering on
               types of notifications:
                   'd'     : Dead-Name notification requested
                   's'     : Send-Possible notification armed
                   'r'     : Send-Possible notification requested
                   'n'     : No-Senders notification requested
                   'x'     : Port-destroy notification requested
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")

    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        print("unknown arguments:", str(cmd_args))
        return False
    rights_type = 0
    if "-R" in cmd_options:
        rights_type = cmd_options["-R"]
    print(GetTaskSummary.header + " " + GetProcSummary.header)
    pval = GetProcFromTask(tval)
    print(GetTaskSummary(tval) + " " + GetProcSummary(pval))
    print(PrintIPCInformation.header)
    PrintIPCInformation(tval.itk_space, True, False, rights_type)

# Count the vouchers in a given task's ipc space
@header("{: <20s} {: <6s} {: <20s} {: <8s}".format("task", "pid", "name", "#vouchers"))
def GetTaskVoucherCount(t):
    is_tableval, num_entries = GetSpaceTable(t.itk_space)
    count = 0
    voucher_kotype = int(GetEnumValue('ipc_kotype_t', 'IKOT_VOUCHER'))

    if is_tableval:
        ports = GetSpaceObjectsWithBits(is_tableval, num_entries, 0x00070000,
            gettype('struct ipc_port'))

        for port in ports:
            io_bits = port.xGetIntegerByPath('.ip_object.io_bits')
            if io_bits & 0x3ff == voucher_kotype:
                count += 1

    format_str = "{: <#20x} {: <6d} {: <20s} {: <8d}"
    pval = GetProcFromTask(t)
    return format_str.format(t, GetProcPID(pval), GetProcNameForTask(t), count)

# Macro: countallvouchers
@lldb_command('countallvouchers', fancy=True)
def CountAllVouchers(cmd_args=None, cmd_options={}, O=None):
    """ Routine to count the number of vouchers by task. Useful for finding leaks.
        Usage: countallvouchers
    """

    with O.table(GetTaskVoucherCount.header):
        for t in kern.tasks:
            print(GetTaskVoucherCount(t))

# Macro: showataskrightsbt

@lldb_command('showtaskrightsbt', 'R:')
def ShowTaskRightsBt(cmd_args=None, cmd_options={}):
    """ Routine to ipc rights information with userstacks for a task
        Usage: showtaskrightsbt [-R rights_type] <task address>
               -R rights_type  : only display rights matching the string 'rights_type'

               types of rights:
                   'Dead'  : Dead name
                   'Set'   : Port set
                   'S'     : Send right
                   'R'     : Receive right
                   'O'     : Send-once right
                   'm'     : Immovable send port
                   'i'     : Immovable receive port
                   'g'     : No grant port
               types of notifications:
                   'd'     : Dead-Name notification requested
                   's'     : Send-Possible notification armed
                   'r'     : Send-Possible notification requested
                   'n'     : No-Senders notification requested
                   'x'     : Port-destroy notification requested
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed")

    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        print("unknown arguments:", str(cmd_args))
        return False
    rights_type = 0
    if "-R" in cmd_options:
        rights_type = cmd_options["-R"]
    print(GetTaskSummary.header + " " + GetProcSummary.header)
    pval = GetProcFromTask(tval)
    print(GetTaskSummary(tval) + " " + GetProcSummary(pval))
    print(PrintIPCInformation.header)
    PrintIPCInformation(tval.itk_space, True, True, rights_type)

# EndMacro: showtaskrightsbt

# Macro: showallrights

@lldb_command('showallrights', 'R:')
def ShowAllRights(cmd_args=None, cmd_options={}):
    """  Routine to print rights information for IPC space of all tasks
         Usage: showallrights [-R rights_type]
                -R rights_type  : only display rights matching the string 'rights_type'

                types of rights:
                    'Dead'  : Dead name
                    'Set'   : Port set
                    'S'     : Send right
                    'R'     : Receive right
                    'O'     : Send-once right
                    'm'     : Immovable send port
                    'i'     : Immovable receive port
                    'g'     : No grant port
                types of notifications:
                    'd'     : Dead-Name notification requested
                    's'     : Send-Possible notification armed
                    'r'     : Send-Possible notification requested
                    'n'     : No-Senders notification requested
                    'x'     : Port-destroy notification requested
    """
    rights_type = 0
    if "-R" in cmd_options:
        rights_type = cmd_options["-R"]
    for t in kern.tasks:
        print(GetTaskSummary.header + " " + GetProcSummary.header)
        pval = GetProcFromTask(t)
        print(GetTaskSummary(t) + " " + GetProcSummary(pval))
        try:
            print(PrintIPCInformation.header)
            PrintIPCInformation(t.itk_space, True, False, rights_type) + "\n\n"
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            print("Failed to get IPC information. Do individual showtaskrights <task> to find the error. \n\n")

# EndMacro: showallrights


def GetInTransitPortSummary(port, disp, holding_port, holding_kmsg):
    """ String-ify the in-transit dispostion of a port.
    """
    ## This should match the summary generated by GetIPCEntrySummary
    ##              "object"   "name"   "rite"  "urefs" "nsets" "nmsgs" "destname" "destination"
    format_str = "\t{: <#20x} {: <12} {: <8s} {: <8d} {: <8d} {: <8d} p:{: <#19x} k:{: <#19x}"
    portname = 'intransit'

    disp_str = GetPortDispositionString(disp)

    out_str = format_str.format(unsigned(port), 'in-transit', disp_str, 0, 0, port.ip_messages.imq_msgcount, unsigned(holding_port), unsigned(holding_kmsg))
    return out_str


def GetDispositionFromEntryType(entry_bits):
    """ Translate an IPC entry type into an in-transit disposition. This allows
        the GetInTransitPortSummary function to be re-used to string-ify IPC
        entry types.
    """
    ebits = int(entry_bits)
    if (ebits & 0x003f0000) == 0:
        return 0

    if (ebits & 0x00010000) != 0:
        return 17 ## MACH_PORT_RIGHT_SEND
    elif (ebits & 0x00020000) != 0:
        return 16 ## MACH_PORT_RIGHT_RECEIVE
    elif (ebits & 0x00040000) != 0:
        return 18 ## MACH_PORT_RIGHT_SEND_ONCE
    elif (ebits & 0x00080000) != 0:
        return 100 ## MACH_PORT_RIGHT_PORT_SET
    elif (ebits & 0x00100000) != 0:
        return 101 ## MACH_PORT_RIGHT_DEAD_NAME
    elif (ebits & 0x00200000) != 0:
        return 102 ## MACH_PORT_RIGHT_LABELH
    else:
        return 0

def GetDispositionFromVoucherPort(th_vport):
    """ Translate a thread's voucher port into a 'disposition'
    """
    if unsigned(th_vport) > 0:
        return 103  ## Voucher type
    return 0


g_kmsg_prog = 0
g_progmeter = {
    0 : '*',
    1 : '-',
    2 : '\\',
    3 : '|',
    4 : '/',
    5 : '-',
    6 : '\\',
    7 : '|',
    8 : '/',
}

def PrintProgressForKmsg():
    global g_kmsg_prog
    global g_progmeter
    sys.stderr.write(" {:<1s}\r".format(g_progmeter[g_kmsg_prog % 9]))
    g_kmsg_prog += 1


def CollectPortsForAnalysis(port, disposition):
    """
    """
    if not port or port == xnudefines.MACH_PORT_DEAD:
        return
    p = Cast(port, 'struct ipc_port *')
    yield (p, disposition)

    # no-senders notification port
    if unsigned(p.ip_nsrequest) not in (0, 1): # 1 is IP_KOBJECT_NSREQUEST_ARMED
        PrintProgressForKmsg()
        yield (p.ip_nsrequest, -1)

    # port-death notification port
    pdrequest = GetPortPDRequest(p)
    if pdrequest:
        PrintProgressForKmsg()
        yield (pdrequest, -2)

    ## ports can have many send-possible notifications armed: go through the table!
    if unsigned(p.ip_requests) != 0:
        table, table_sz = kalloc_array_decode(p.ip_requests, 'struct ipc_port_request')
        for i in range(table_sz):
            if i == 0:
                continue
            ipr = table[i]
            if unsigned(ipr.ipr_name) in (0, 0xfffffffe):
                # 0xfffffffe is a host notify request
                continue
            ipr_bits = unsigned(ipr.ipr_soright) & 3
            ipr_port = kern.GetValueFromAddress(int(ipr.ipr_soright) & ~3, 'struct ipc_port *')
            # skip unused entries in the ipc table to avoid null dereferences
            if not ipr_port:
                continue
            ipr_disp = 0
            if ipr_bits & 3: ## send-possible armed and requested
                ipr_disp = -5
            elif ipr_bits & 2: ## send-possible requested
                ipr_disp = -4
            elif ipr_bits & 1: ## send-possible armed
                ipr_disp = -3
            PrintProgressForKmsg()
            yield (ipr_port, ipr_disp)
    return

def CollectKmsgPorts(task, task_port, kmsgp):
    """ Look through a message, 'kmsgp' destined for 'task'
        (enqueued on task_port). Collect any port descriptors,
        remote, local, voucher, or other port references
        into a (ipc_port_t, disposition) list.
    """
    kmsgh = dereference(GetKmsgHeader(kmsgp))

    p_list = []

    PrintProgressForKmsg()
    if kmsgh.msgh_remote_port and unsigned(kmsgh.msgh_remote_port) != unsigned(task_port):
        disp = kmsgh.msgh_bits & 0x1f
        p_list += list(CollectPortsForAnalysis(kmsgh.msgh_remote_port, disp))

    if kmsgh.msgh_local_port and unsigned(kmsgh.msgh_local_port) != unsigned(task_port) \
       and unsigned(kmsgh.msgh_local_port) != unsigned(kmsgh.msgh_remote_port):
        disp = (kmsgh.msgh_bits & 0x1f00) >> 8
        p_list += list(CollectPortsForAnalysis(kmsgh.msgh_local_port, disp))

    if kmsgp.ikm_voucher_port:
        p_list += list(CollectPortsForAnalysis(kmsgp.ikm_voucher_port, 0))

    if kmsgh.msgh_bits & 0x80000000:
        ## Complex message - look for descriptors
        PrintProgressForKmsg()
        (body, dschead, dsc_list) = GetKmsgDescriptors(kmsgp)
        for dsc in dsc_list:
            PrintProgressForKmsg()
            dsc_type = unsigned(dsc.type.type)
            if dsc_type == 0 or dsc_type == 2: ## 0 == port, 2 == ool port
                if dsc_type == 0:
                    ## its a port descriptor
                    dsc_disp = dsc.port.disposition
                    p_list += list(CollectPortsForAnalysis(dsc.port.name, dsc_disp))
                else:
                    ## it's an ool_ports descriptor which is an array of ports
                    dsc_disp = dsc.ool_ports.disposition
                    dispdata = Cast(dsc.ool_ports.address, 'struct ipc_port *')
                    for pidx in range(dsc.ool_ports.count):
                        PrintProgressForKmsg()
                        p_list += list(CollectPortsForAnalysis(dispdata[pidx], dsc_disp))
    return p_list

def CollectKmsgPortRefs(task, task_port, kmsgp, p_refs):
    """ Recursively collect all references to ports inside the kmsg 'kmsgp'
        into the set 'p_refs'
    """
    p_list = CollectKmsgPorts(task, task_port, kmsgp)

    ## Iterate over each ports we've collected, to see if they
    ## have messages on them, and then recurse!
    for p, pdisp in p_list:
        ptype = (p.ip_object.io_bits & 0x7fff0000) >> 16
        p_refs.add((p, pdisp, ptype))
        if ptype != 0: ## don't bother with port sets
            continue
        ## If the port that's in-transit has messages already enqueued,
        ## go through each of those messages and look for more ports!
        for p_kmsgp in IterateCircleQueue(p.ip_messages.imq_messages, 'ipc_kmsg', 'ikm_link'):
            CollectKmsgPortRefs(task, p, p_kmsgp, p_refs)


def FindKmsgPortRefs(instr, task, task_port, kmsgp, qport):
    """ Look through a message, 'kmsgp' destined for 'task'. If we find
        any port descriptors, remote, local, voucher, or other port that
        matches 'qport', return a short description
        which should match the format of GetIPCEntrySummary.
    """

    out_str = instr
    p_list = CollectKmsgPorts(task, task_port, kmsgp)

    ## Run through all ports we've collected looking for 'qport'
    for p, pdisp in p_list:
        PrintProgressForKmsg()
        if unsigned(p) == unsigned(qport):
            ## the port we're looking for was found in this message!
            if len(out_str) > 0:
                out_str += '\n'
            out_str += GetInTransitPortSummary(p, pdisp, task_port, kmsgp)

        ptype = (p.ip_object.io_bits & 0x7fff0000) >> 16
        if ptype != 0: ## don't bother with port sets
            continue

        ## If the port that's in-transit has messages already enqueued,
        ## go through each of those messages and look for more ports!
        for p_kmsgp in IterateCircleQueue(p.ip_messages.imq_messages, 'ipc_kmsg', 'ikm_link'):
            out_str = FindKmsgPortRefs(out_str, task, p, p_kmsgp, qport)

    return out_str


port_iteration_do_print_taskname = False
registeredport_idx = -10
excports_idx = -20
intransit_idx = -1000
taskports_idx = -2000
thports_idx = -3000

def IterateAllPorts(tasklist, func, ctx, include_psets, follow_busyports, should_log):
    """ Iterate over all ports in the system, calling 'func'
        for each entry in 
    """
    global port_iteration_do_print_taskname
    global intransit_idx, taskports_idx, thports_idx, registeredport_idx, excports_idx

    ## XXX: also host special ports

    entry_port_type_mask = 0x00070000
    if include_psets:
        entry_port_type_mask = 0x000f0000

    if tasklist is None:
        tasklist = list(kern.tasks)
        tasklist += list(kern.terminated_tasks)

    tidx = 1

    for t in tasklist:
        # Write a progress line.  Using stderr avoids automatic newline when
        # writing to stdout from lldb.  Blank spaces at the end clear out long
        # lines.
        if should_log:
            procname = ""
            if not t.active:
                procname = 'terminated: '
            if t.halting:
                procname += 'halting: '
            procname += GetProcNameForTask(t)
            sys.stderr.write("  checking {:s} ({}/{})...{:50s}\r".format(procname, tidx, len(tasklist), ''))
        tidx += 1

        port_iteration_do_print_taskname = True
        space = t.itk_space
        is_tableval, num_entries = GetSpaceTable(space)

        if not is_tableval:
            continue

        base  = is_tableval.GetSBValue().Dereference()
        entries = (
            value(iep.AddressOf())
            for iep in base.xIterSiblings(1, num_entries)
        )

        for idx, entry_val in enumerate(entries, 1):
            entry_bits= unsigned(entry_val.ie_bits)
            entry_obj = 0
            entry_str = ''
            entry_name = "{:x}".format( (idx << 8 | entry_bits >> 24) )

            entry_disp = GetDispositionFromEntryType(entry_bits)

            ## If the entry in the table represents a port of some sort,
            ## then make the callback provided
            if int(entry_bits) & entry_port_type_mask:
                eport = kern.CreateTypedPointerFromAddress(unsigned(entry_val.ie_object), 'struct ipc_port')
                ## Make the callback
                func(t, space, ctx, idx, entry_val, eport, entry_disp)

                ## if the port has pending messages, look through
                ## each message for ports (and recurse)
                if follow_busyports and unsigned(eport) > 0 and eport.ip_messages.imq_msgcount > 0:
                    ## collect all port references from all messages
                    for kmsgp in IterateCircleQueue(eport.ip_messages.imq_messages, 'ipc_kmsg', 'ikm_link'):
                        p_refs = set()
                        CollectKmsgPortRefs(t, eport, kmsgp, p_refs)
                        for (port, pdisp, ptype) in p_refs:
                            func(t, space, ctx, intransit_idx, None, port, pdisp)
        ## for idx in xrange(1, num_entries)

        ## Task ports (send rights)
        if getattr(t, 'itk_settable_self', 0) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_settable_self, 17)
        if unsigned(t.itk_host) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_host, 17)
        if unsigned(t.itk_bootstrap) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_bootstrap, 17)
        if unsigned(t.itk_debug_control) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_debug_control, 17)
        if unsigned(t.itk_task_access) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_task_access, 17)
        if unsigned(t.itk_task_ports[1]) > 0: ## task read port
            func(t, space, ctx, taskports_idx, 0, t.itk_task_ports[1], 17)
        if unsigned(t.itk_task_ports[2]) > 0: ## task inspect port
            func(t, space, ctx, taskports_idx, 0, t.itk_task_ports[2], 17)

        ## Task name port (not a send right, just a naked ref); TASK_FLAVOR_NAME = 3
        if unsigned(t.itk_task_ports[3]) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_task_ports[3], 0)

        ## task resume port is a receive right to resume the task
        if unsigned(t.itk_resume) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_resume, 16)

        ## registered task ports (all send rights)
        tr_idx = 0
        tr_max = sizeof(t.itk_registered) // sizeof(t.itk_registered[0])
        while tr_idx < tr_max:
            tport = t.itk_registered[tr_idx]
            if unsigned(tport) > 0:
                try:
                    func(t, space, ctx, registeredport_idx, 0, tport, 17)
                except Exception as e:
                    print("\texception looking through registered port {:d}/{:d} in {:s}".format(tr_idx,tr_max,t))
                    pass
            tr_idx += 1

        ## Task exception ports
        exidx = 0
        exmax = sizeof(t.exc_actions) // sizeof(t.exc_actions[0])
        while exidx < exmax: ## see: osfmk/mach/[arm|i386]/exception.h
            export = t.exc_actions[exidx].port ## send right
            if unsigned(export) > 0:
                try:
                    func(t, space, ctx, excports_idx, 0, export, 17)
                except Exception as e:
                    print("\texception looking through exception port {:d}/{:d} in {:s}".format(exidx,exmax,t))
                    pass
            exidx += 1

        ## XXX: any  ports still valid after clearing IPC space?!

        for thval in IterateQueue(t.threads, 'thread *', 'task_threads'):
            ## XXX: look at block reason to see if it's in mach_msg_receive - then look at saved state / message

            ## Thread port (send right)
            if getattr(thval.t_tro, 'tro_settable_self_port', 0) > 0:
                thport = thval.t_tro.tro_settable_self_port
                func(t, space, ctx, thports_idx, 0, thport, 17) ## see: osfmk/mach/message.h
            ## Thread special reply port (send-once right)
            if unsigned(thval.ith_special_reply_port) > 0:
                thport = thval.ith_special_reply_port
                func(t, space, ctx, thports_idx, 0, thport, 18) ## see: osfmk/mach/message.h
            ## Thread voucher port
            if unsigned(thval.ith_voucher) > 0:
                vport = thval.ith_voucher.iv_port
                if unsigned(vport) > 0:
                    vdisp = GetDispositionFromVoucherPort(vport)
                    func(t, space, ctx, thports_idx, 0, vport, vdisp)
            ## Thread exception ports
            if unsigned(thval.t_tro.tro_exc_actions) > 0:
                exidx = 0
                while exidx < exmax: ## see: osfmk/mach/[arm|i386]/exception.h
                    export = thval.t_tro.tro_exc_actions[exidx].port ## send right
                    if unsigned(export) > 0:
                        try:
                            func(t, space, ctx, excports_idx, 0, export, 17)
                        except Exception as e:
                            print("\texception looking through exception port {:d}/{:d} in {:s}".format(exidx,exmax,t))
                            pass
                    exidx += 1
            ## XXX: the message on a thread (that's currently being received)
        ## for (thval in t.threads)
    ## for (t in tasklist)


# Macro: findportrights
def FindPortRightsCallback(task, space, ctx, entry_idx, ipc_entry, ipc_port, port_disp):
    """ Callback which uses 'ctx' as the (port,rights_types) tuple for which
        a caller is seeking references. This should *not* be used from a
        recursive call to IterateAllPorts.
    """
    global port_iteration_do_print_taskname

    (qport, rights_type) = ctx
    entry_name = ''
    entry_str = ''
    if unsigned(ipc_entry) != 0:
        entry_bits = unsigned(ipc_entry.ie_bits)
        entry_name = "{:x}".format( (entry_idx << 8 | entry_bits >> 24) )
        if (int(entry_bits) & 0x001f0000) != 0 and unsigned(ipc_entry.ie_object) == unsigned(qport):
            ## it's a valid entry, and it points to the port
            entry_str = '\t' + GetIPCEntrySummary(ipc_entry, entry_name, rights_type)

    procname = GetProcNameForTask(task)
    if ipc_port and ipc_port != xnudefines.MACH_PORT_DEAD and ipc_port.ip_messages.imq_msgcount > 0:
        sys.stderr.write("  checking {:s} busy-port {}:{:#x}...{:30s}\r".format(procname, entry_name, unsigned(ipc_port), ''))
        ## Search through busy ports to find descriptors which could
        ## contain the only reference to this port!
        for kmsgp in IterateCircleQueue(ipc_port.ip_messages.imq_messages, 'ipc_kmsg', 'ikm_link'):
            entry_str = FindKmsgPortRefs(entry_str, task, ipc_port, kmsgp, qport)

    if len(entry_str) > 0:
        sys.stderr.write("{:80s}\r".format(''))
        if port_iteration_do_print_taskname:
            print("Task: {0: <#x} {1: <s}".format(task, procname))
            print('\t' + GetIPCEntrySummary.header)
            port_iteration_do_print_taskname = False
        print(entry_str)

@lldb_command('findportrights', 'R:S:')
def FindPortRights(cmd_args=None, cmd_options={}):
    """  Routine to locate and print all extant rights to a given port
         Usage: findportrights [-R rights_type] [-S <ipc_space_t>] <ipc_port_t>
                -S ipc_space    : only search the specified ipc space
                -R rights_type  : only display rights matching the string 'rights_type'

                types of rights:
                    'Dead'  : Dead name
                    'Set'   : Port set
                    'S'     : Send right
                    'R'     : Receive right
                    'O'     : Send-once right
                types of notifications:
                    'd'     : Dead-Name notification requested
                    's'     : Send-Possible notification armed
                    'r'     : Send-Possible notification requested
                    'n'     : No-Senders notification requested
                    'x'     : Port-destroy notification requested
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("no port address provided")
    port = kern.GetValueFromAddress(cmd_args[0], 'struct ipc_port *')

    rights_type = 0
    if "-R" in cmd_options:
        rights_type = cmd_options["-R"]

    tasklist = None
    if "-S" in cmd_options:
        space = kern.GetValueFromAddress(cmd_options["-S"], 'struct ipc_space *')
        tasklist = [ space.is_task ]

    ## Don't include port sets
    ## Don't recurse on busy ports (we do that manually)
    ## DO log progress
    IterateAllPorts(tasklist, FindPortRightsCallback, (port, rights_type), False, False, True)
    sys.stderr.write("{:120s}\r".format(' '))

    print("Done.")
# EndMacro: findportrights

# Macro: countallports

def CountPortsCallback(task, space, ctx, entry_idx, ipc_entry, ipc_port, port_disp):
    """ Callback which uses 'ctx' as the set of all ports found in the
        iteration. This should *not* be used from a recursive
        call to IterateAllPorts.
    """
    global intransit_idx

    (p_set, p_intransit, p_bytask) = ctx

    ## Add the port address to the set of all port addresses
    ipc_port_addr = unsigned(ipc_port)
    p_set.add(ipc_port_addr)

    if entry_idx == intransit_idx:
        p_intransit.add(ipc_port_addr)

    if task.active or (task.halting and not task.active):
        if not task in p_bytask:
            p_bytask[task] = { 'transit':0, 'table':0, 'other':0 }
        if entry_idx == intransit_idx:
            p_bytask[task]['transit'] += 1
        elif entry_idx >= 0:
            p_bytask[task]['table'] += 1
        else:
            p_bytask[task]['other'] += 1

@header(f"{'#ports': <10s} {'in transit': <10s} {'Special': <10s}")           
@lldb_command('countallports', 'P', fancy=True)
def CountAllPorts(cmd_args=None, cmd_options={}, O=None):
    """ Routine to search for all as many references to ipc_port structures in the kernel
        that we can find.
        Usage: countallports [-P]
                -P : include port sets in the count (default: NO)
    """
    p_set = set()
    p_intransit = set()
    p_bytask = {}

    find_psets = False
    if "-P" in cmd_options:
        find_psets = True

    ## optionally include port sets
    ## DO recurse on busy ports
    ## DO log progress
    IterateAllPorts(None, CountPortsCallback, (p_set, p_intransit, p_bytask), find_psets, True, True)
    sys.stderr.write(f"{' ':120s}\r")

    # sort by ipc table size 
    with O.table(GetTaskIPCSummary.header + ' ' + CountAllPorts.header):
        for task, port_summary in sorted(p_bytask.items(), key=lambda item: item[1]['table'], reverse=True):
            outstring, _ = GetTaskIPCSummary(task)
            outstring += f" {port_summary['table']: <10d} {port_summary['transit']: <10d} {port_summary['other']: <10d}"
            print(outstring)
    
    print(f"\nTotal ports found: {len(p_set)}")
    print(f"Number of ports In Transit: {len(p_intransit)}")
    
# EndMacro: countallports
# Macro: showpipestats

@lldb_command('showpipestats')
def ShowPipeStats(cmd_args=None):
    """ Display pipes usage information in the kernel
    """
    print("Number of pipes: {: d}".format(kern.globals.amountpipes))
    print("Memory used by pipes: {:s}".format(sizeof_fmt(int(kern.globals.amountpipekva))))
    print("Max memory allowed for pipes: {:s}".format(sizeof_fmt(int(kern.globals.maxpipekva))))

# EndMacro: showpipestats
# Macro: showtaskbusyports

@lldb_command('showtaskbusyports', fancy=True)
def ShowTaskBusyPorts(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print information about receive rights belonging to this task that
        have enqueued messages. This is often a sign of a blocked or hung process
        Usage: showtaskbusyports <task address>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed. Please pass in the address of a task")

    task = kern.GetValueFromAddress(cmd_args[0], 'task_t')
    is_tableval, num_entries = GetSpaceTable(task.itk_space)

    if is_tableval:
        ports = GetSpaceObjectsWithBits(is_tableval, num_entries, 0x00020000,
            gettype('struct ipc_port'))

        with O.table(PrintPortSummary.header):
            for port in ports:
                if port.xGetIntegerByPath('.ip_messages.imq_msgcount'):
                    PrintPortSummary(value(port.AddressOf()), O=O)

# EndMacro: showtaskbusyports
# Macro: showallbusyports

@lldb_command('showallbusyports', fancy=True)
def ShowAllBusyPorts(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print information about all receive rights on the system that
        have enqueued messages.
    """
    with O.table(PrintPortSummary.header):
        port_ty = gettype("struct ipc_port")
        for port in kmemory.Zone("ipc ports").iter_allocated(port_ty):
            if port.xGetIntegerByPath('.ip_messages.imq_msgcount') > 0:
                PrintPortSummary(value(port.AddressOf()), O=O)

# EndMacro: showallbusyports
# Macro: showallports

@lldb_command('showallports', fancy=True)
def ShowAllPorts(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print information about all allocated ports in the system

        usage: showallports
    """
    with O.table(PrintPortSummary.header):
        port_ty = gettype("struct ipc_port")
        for port in kmemory.Zone("ipc ports").iter_allocated(port_ty):
            PrintPortSummary(value(port.AddressOf()), show_kmsg_summary=False, O=O)

# EndMacro: showallports
# Macro: findkobjectport

@lldb_command('findkobjectport', fancy=True)
def FindKobjectPort(cmd_args=None, cmd_options={}, O=None):
    """ Locate all ports pointing to a given kobject

        usage: findkobjectport <kobject-addr>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError()

    kobj_addr = unsigned(kern.GetValueFromAddress(cmd_args[0]))
    kmem = kmemory.KMem.get_shared()
    port_ty = gettype("struct ipc_port")

    with O.table(PrintPortSummary.header):
        for port in kmemory.Zone("ipc ports").iter_allocated(port_ty):
            if port.xGetIntegerByPath('.ip_object.io_bits') & 0x3ff == 0:
                continue

            ip_kobject = kmem.make_address(port.xGetScalarByName('ip_kobject'))
            if ip_kobject == kobj_addr:
                PrintPortSummary(value(port.AddressOf()), show_kmsg_summary=False, O=O)

# EndMacro: findkobjectport
# Macro: showtaskbusypsets

@lldb_command('showtaskbusypsets', fancy=True)
def ShowTaskBusyPortSets(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print information about port sets belonging to this task that
        have enqueued messages. This is often a sign of a blocked or hung process
        Usage: showtaskbusypsets <task address>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("No arguments passed. Please pass in the address of a task")

    task = kern.GetValueFromAddress(cmd_args[0], 'task_t')
    is_tableval, num_entries = GetSpaceTable(task.itk_space)

    if is_tableval:
        psets = GetSpaceObjectsWithBits(is_tableval, num_entries, 0x00080000,
            gettype('struct ipc_pset'))

        with O.table(PrintPortSetSummary.header):
            for pset in (value(v.AddressOf()) for v in psets):
                for wq in Waitq(addressof(pset.ips_wqset)).iterateMembers():
                    if wq.asPort().ip_messages.imq_msgcount > 0:
                        PrintPortSetSummary(pset, space=task.itk_space, O=O)

# EndMacro: showtaskbusyports
# Macro: showallbusypsets

@lldb_command('showallbusypsets', fancy=True)
def ShowAllBusyPortSets(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print information about all port sets on the system that
        have enqueued messages.
    """
    with O.table(PrintPortSetSummary.header):
        pset_ty = gettype("struct ipc_pset")
        for pset in kmemory.Zone("ipc port sets").iter_allocated(pset_ty):
            pset = value(pset.AddressOf())
            for wq in Waitq(addressof(pset.ips_wqset)).iterateMembers():
                port = wq.asPort()
                if port.ip_messages.imq_msgcount > 0:
                    PrintPortSetSummary(pset, space=port.ip_receiver, O=O)

# EndMacro: showallbusyports
# Macro: showallpsets

@lldb_command('showallpsets', fancy=True)
def ShowAllPortSets(cmd_args=None, cmd_options={}, O=None):
    """ Routine to print information about all allocated psets in the system

        usage: showallpsets
    """
    with O.table(PrintPortSetSummary.header):
        pset_ty = gettype("struct ipc_pset")
        for pset in kmemory.Zone("ipc port sets").iter_allocated(pset_ty):
            PrintPortSetSummary(value(pset.AddressOf()), O=O)

# EndMacro: showallports
# Macro: showbusyportsummary

@lldb_command('showbusyportsummary')
def ShowBusyPortSummary(cmd_args=None):
    """ Routine to print a summary of information about all receive rights
        on the system that have enqueued messages.
    """
    task_queue_head = kern.globals.tasks

    ipc_table_size = 0
    ipc_busy_ports = 0
    ipc_msgs = 0

    print(GetTaskBusyIPCSummary.header)
    for tsk in kern.tasks:
        (summary, table_size, nbusy, nmsgs) = GetTaskBusyIPCSummary(tsk)
        ipc_table_size += table_size
        ipc_busy_ports += nbusy
        ipc_msgs += nmsgs
        print(summary)
    for tsk in kern.terminated_tasks:
        (summary, table_size, nbusy, nmsgs) = GetTaskBusyIPCSummary(tsk)
        ipc_table_size += table_size
        ipc_busy_ports += nbusy
        ipc_msgs += nmsgs
        print(summary)
    print("Total Table Size: {:d}, Busy Ports: {:d}, Messages in-flight: {:d}".format(ipc_table_size, ipc_busy_ports, ipc_msgs))
    return

# EndMacro: showbusyportsummary
# Macro: showport / showpset

def ShowPortOrPset(obj, space=0, O=None):
    """ Routine that lists details about a given IPC port or pset
        Syntax: (lldb) showport 0xaddr
    """
    if not obj or obj == xnudefines.IPC_OBJECT_DEAD:
        print("IPC_OBJECT_DEAD")
        return

    otype = (obj.io_bits & 0x7fff0000) >> 16
    if otype == 0: # IOT_PORT
        with O.table(PrintPortSummary.header):
            PrintPortSummary(cast(obj, 'ipc_port_t'), show_sets=True, O=O)
    elif otype == 1: # IOT_PSET
        with O.table(PrintPortSetSummary.header):
            PrintPortSetSummary(cast(obj, 'ipc_pset_t'), space, O=O)

@lldb_command('showport', 'K', fancy=True)
def ShowPort(cmd_args=None, cmd_options={}, O=None):
    """ Routine that lists details about a given IPC port 

        usage: showport <address>
    """
    # -K is default and kept for backward compat, it used to mean "show kmsg queue"
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Missing port argument")

    obj = kern.GetValueFromAddress(cmd_args[0], 'struct ipc_object *')
    ShowPortOrPset(obj, O=O)


@lldb_command('showpset', "S:", fancy=True)
def ShowPSet(cmd_args=None, cmd_options={}, O=None):
    """ Routine that prints details for a given ipc_pset *

        usage: showpset [-S <space>] <address>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Missing port argument")

    space = 0
    if "-S" in cmd_options:
        space = kern.GetValueFromAddress(cmd_options["-S"], 'struct ipc_space *')
    obj = kern.GetValueFromAddress(cmd_args[0], 'struct ipc_object *')
    ShowPortOrPset(obj, space=space, O=O)

# EndMacro: showport / showpset
# Macro: showkmsg:

@lldb_command('showkmsg')
def ShowKMSG(cmd_args=[]):
    """ Show detail information about a <ipc_kmsg_t> structure
        Usage: (lldb) showkmsg <ipc_kmsg_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError('Invalid arguments')

    kmsg = kern.GetValueFromAddress(cmd_args[0], 'ipc_kmsg_t')
    print(GetKMsgSummary.header)
    print(GetKMsgSummary(kmsg))

# EndMacro: showkmsg
# IPC importance inheritance related macros.

@lldb_command('showalliits')
def ShowAllIITs(cmd_args=[], cmd_options={}):
    """ Development only macro. Show list of all iits allocated in the system. """
    try:
        iit_queue = kern.globals.global_iit_alloc_queue
    except ValueError:
        print("This debug macro is only available in development or debug kernels")
        return

    print(GetIPCImportantTaskSummary.header)
    for iit in IterateQueue(iit_queue, 'struct ipc_importance_task *', 'iit_allocation'):
        print(GetIPCImportantTaskSummary(iit))
    return

@header("{: <18s} {: <3s} {: <18s} {: <32s} {: <18s} {: <8s}".format("ipc_imp_inherit", "don", "to_task", "proc_name", "from_elem", "depth"))
@lldb_type_summary(['ipc_importance_inherit *', 'ipc_importance_inherit_t'])
def GetIPCImportanceInheritSummary(iii):
    """ describes iii object of type ipc_importance_inherit_t * """
    out_str = ""
    fmt = "{o: <#18x} {don: <3s} {o.iii_to_task.iit_task: <#18x} {task_name: <20s} {o.iii_from_elem: <#18x} {o.iii_depth: <#8x}"
    donating_str = ""
    if unsigned(iii.iii_donating):
        donating_str = "DON"
    taskname = GetProcNameForTask(iii.iii_to_task.iit_task)
    if hasattr(iii.iii_to_task, 'iit_bsd_pid'):
        taskname =  "({:d}) {:s}".format(iii.iii_to_task.iit_bsd_pid, iii.iii_to_task.iit_procname)
    out_str += fmt.format(o=iii, task_name = taskname, don=donating_str)
    return out_str

@static_var('recursion_count', 0)
@header("{: <18s} {: <4s} {: <8s} {: <8s} {: <18s} {: <18s}".format("iie", "type", "refs", "made", "#kmsgs", "#inherits"))
@lldb_type_summary(['ipc_importance_elem *'])
def GetIPCImportanceElemSummary(iie):
    """ describes an ipc_importance_elem * object """

    if GetIPCImportanceElemSummary.recursion_count > 500:
        GetIPCImportanceElemSummary.recursion_count = 0
        return "Recursion of 500 reached"

    out_str = ''
    fmt = "{: <#18x} {: <4s} {: <8d} {: <8d} {: <#18x} {: <#18x}"
    if unsigned(iie.iie_bits) & xnudefines.IIE_TYPE_MASK:
        type_str = "INH"
        inherit_count = 0
    else:
        type_str = 'TASK'
        iit = Cast(iie, 'struct ipc_importance_task *')
        inherit_count = sum(1 for i in IterateQueue(iit.iit_inherits, 'struct ipc_importance_inherit *',  'iii_inheritance'))

    refs = unsigned(iie.iie_bits) >> xnudefines.IIE_TYPE_BITS
    made_refs = unsigned(iie.iie_made)
    kmsg_count = sum(1 for i in IterateQueue(iie.iie_kmsgs, 'struct ipc_kmsg *',  'ikm_inheritance'))
    out_str += fmt.format(iie, type_str, refs, made_refs, kmsg_count, inherit_count)
    if config['verbosity'] > vHUMAN:
        if kmsg_count > 0:
            out_str += "\n\t"+ GetKMsgSummary.header
            for k in IterateQueue(iie.iie_kmsgs, 'struct ipc_kmsg *',  'ikm_inheritance'):
                out_str += "\t" + "{: <#18x}".format(GetKmsgHeader(k).msgh_remote_port) + '   ' + GetKMsgSummary(k, "\t").lstrip()
            out_str += "\n"
        if inherit_count > 0:
            out_str += "\n\t" + GetIPCImportanceInheritSummary.header + "\n"
            for i in IterateQueue(iit.iit_inherits, 'struct ipc_importance_inherit *',  'iii_inheritance'):
                out_str += "\t" + GetIPCImportanceInheritSummary(i) + "\n"
            out_str += "\n"
        if type_str == "INH":
            iii = Cast(iie, 'struct ipc_importance_inherit *')
            out_str += "Inherit from: " + GetIPCImportanceElemSummary(iii.iii_from_elem)

    return out_str

@header("{: <18s} {: <18s} {: <32}".format("iit", "task", "name"))
@lldb_type_summary(['ipc_importance_task *'])
def GetIPCImportantTaskSummary(iit):
    """ iit is a ipc_importance_task value object.
    """
    fmt = "{: <#18x} {: <#18x} {: <32}"
    out_str=''
    pname = GetProcNameForTask(iit.iit_task)
    if hasattr(iit, 'iit_bsd_pid'):
        pname = "({:d}) {:s}".format(iit.iit_bsd_pid, iit.iit_procname)
    out_str += fmt.format(iit, iit.iit_task, pname)
    return out_str

@lldb_command('showallimportancetasks')
def ShowIPCImportanceTasks(cmd_args=[], cmd_options={}):
    """ display a list of all tasks with ipc importance information. 
        Usage: (lldb) showallimportancetasks
        Tip: add "-v" to see detailed information on each kmsg or inherit elems 
    """
    print(' ' + GetIPCImportantTaskSummary.header + ' ' + GetIPCImportanceElemSummary.header)
    for t in kern.tasks:
        s = ""
        if unsigned(t.task_imp_base):
            s += ' ' + GetIPCImportantTaskSummary(t.task_imp_base)
            s += ' ' + GetIPCImportanceElemSummary(addressof(t.task_imp_base.iit_elem))
            print(s)

@lldb_command('showipcimportance', '')
def ShowIPCImportance(cmd_args=[], cmd_options={}):
    """ Describe an importance from <ipc_importance_elem_t> argument.
        Usage: (lldb) showimportance <ipc_importance_elem_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Please provide valid argument")

    elem = kern.GetValueFromAddress(cmd_args[0], 'ipc_importance_elem_t')
    print(GetIPCImportanceElemSummary.header)
    print(GetIPCImportanceElemSummary(elem))

@header("{: <18s} {: <18s} {: <8s} {: <5s} {: <5s} {: <8s}".format("ivac", "tbl", "tblsize", "index", "Grow", "freelist"))
@lldb_type_summary(['ipc_voucher_attr_control *', 'ipc_voucher_attr_control_t'])
def GetIPCVoucherAttrControlSummary(ivac):
    """ describes a voucher attribute control settings """
    out_str = ""
    fmt = "{c: <#18x} {c.ivac_table: <#18x} {c.ivac_table_size: <8d} {c.ivac_key_index: <5d} {growing: <5s} {c.ivac_freelist: <8d}"
    growing_str = ""

    if ivac == 0:
        return "{: <#18x}".format(ivac)

    growing_str = "Y" if unsigned(ivac.ivac_is_growing) else "N"    
    out_str += fmt.format(c=ivac, growing = growing_str)
    return out_str

@lldb_command('showivac','')
def ShowIPCVoucherAttributeControl(cmd_args=[], cmd_options={}):
    """ Show summary of voucher attribute contols.
        Usage: (lldb) showivac <ipc_voucher_attr_control_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Please provide correct arguments.")
    ivac = kern.GetValueFromAddress(cmd_args[0], 'ipc_voucher_attr_control_t')
    print(GetIPCVoucherAttrControlSummary.header)
    print(GetIPCVoucherAttrControlSummary(ivac))
    if config['verbosity'] > vHUMAN:
        cur_entry_index = 0
        last_entry_index = unsigned(ivac.ivac_table_size)
        print("index " + GetIPCVoucherAttributeEntrySummary.header)
        while cur_entry_index < last_entry_index:
            print("{: <5d} ".format(cur_entry_index) + GetIPCVoucherAttributeEntrySummary(addressof(ivac.ivac_table[cur_entry_index])))
            cur_entry_index += 1




@header("{: <18s} {: <30s} {: <30s} {: <30s} {: <30s}".format("ivam", "get_value_fn", "extract_fn", "release_value_fn", "command_fn"))
@lldb_type_summary(['ipc_voucher_attr_manager *', 'ipc_voucher_attr_manager_t'])
def GetIPCVoucherAttrManagerSummary(ivam):
    """ describes a voucher attribute manager settings """
    out_str = ""
    fmt = "{: <#18x} {: <30s} {: <30s} {: <30s} {: <30s}"

    if unsigned(ivam) == 0 :
        return "{: <#18x}".format(ivam)

    get_value_fn = kern.Symbolicate(unsigned(ivam.ivam_get_value))
    extract_fn = kern.Symbolicate(unsigned(ivam.ivam_extract_content))
    release_value_fn = kern.Symbolicate(unsigned(ivam.ivam_release_value))
    command_fn = kern.Symbolicate(unsigned(ivam.ivam_command))
    out_str += fmt.format(ivam, get_value_fn, extract_fn, release_value_fn, command_fn)
    return out_str

def iv_key_to_index(key):
    """ ref: osfmk/ipc/ipc_voucher.c: iv_key_to_index """
    if (key == xnudefines.MACH_VOUCHER_ATTR_KEY_ALL) or (key > xnudefines.MACH_VOUCHER_ATTR_KEY_NUM):
        return xnudefines.IV_UNUSED_KEYINDEX
    return key - 1

def iv_index_to_key(index):
    """ ref: osfmk/ipc/ipc_voucher.c: iv_index_to_key """
    if index < xnudefines.MACH_VOUCHER_ATTR_KEY_NUM_WELL_KNOWN:
        return index + 1
    return xnudefines.MACH_VOUCHER_ATTR_KEY_NONE

@header("{: <3s} {: <3s} {:s} {:s}".format("idx", "key", GetIPCVoucherAttrControlSummary.header.strip(), GetIPCVoucherAttrManagerSummary.header.strip()))
@lldb_type_summary(['ipc_voucher_global_table_element *', 'ipc_voucher_global_table_element_t'])
def GetIPCVoucherGlobalTableElementSummary(idx, ivac, ivam):
    """ describes a ipc_voucher_global_table_element object """
    out_str = ""
    fmt = "{idx: <3d} {key: <3d} {ctrl_s:s} {mgr_s:s}"
    out_str += fmt.format(idx=idx, key=iv_index_to_key(idx), ctrl_s=GetIPCVoucherAttrControlSummary(addressof(ivac)), mgr_s=GetIPCVoucherAttrManagerSummary(ivam))
    return out_str

@lldb_command('showglobalvouchertable', '')
def ShowGlobalVoucherTable(cmd_args=[], cmd_options={}):
    """ show detailed information of all voucher attribute managers registered with vouchers system
        Usage: (lldb) showglobalvouchertable
    """
    entry_size = sizeof(kern.globals.ivac_global_table[0])
    elems = sizeof(kern.globals.ivac_global_table) // entry_size
    print(GetIPCVoucherGlobalTableElementSummary.header)
    for i in range(elems):
        ivac = kern.globals.ivac_global_table[i]
        ivam = kern.globals.ivam_global_table[i]
        if unsigned(ivam) == 0:
            continue
        print(GetIPCVoucherGlobalTableElementSummary(i, ivac, ivam))

# Type summaries for Bag of Bits.

@lldb_type_summary(['user_data_value_element', 'user_data_element_t'])
@header("{0: <20s} {1: <16s} {2: <20s} {3: <20s} {4: <16s} {5: <20s}".format("user_data_ve", "maderefs", "checksum", "hash value", "size", "data"))
def GetBagofBitsElementSummary(data_element):
    """ Summarizes the Bag of Bits element
        params: data_element = value of the object of type user_data_value_element_t
        returns: String with summary of the type.
    """
    format_str = "{0: <#20x} {1: <16d} {2: <#20x} {3: <#20x} {4: <16d}"
    out_string = format_str.format(data_element, unsigned(data_element.e_made), data_element.e_sum, data_element.e_hash, unsigned(data_element.e_size))
    out_string += " 0x"

    for i in range(0, (unsigned(data_element.e_size) - 1)):
        out_string += "{:02x}".format(int(data_element.e_data[i]))
    return out_string

def GetIPCHandleSummary(handle_ptr):
    """ converts a handle value inside a voucher attribute table to ipc element and returns appropriate summary.
        params: handle_ptr - uint64 number stored in handle of voucher.
        returns: str - string summary of the element held in internal structure
    """
    elem = kern.GetValueFromAddress(handle_ptr, 'ipc_importance_elem_t')
    if elem.iie_bits & xnudefines.IIE_TYPE_MASK:
        iie = Cast(elem, 'struct ipc_importance_inherit *')
        return GetIPCImportanceInheritSummary(iie)
    else:
        iit = Cast(elem, 'struct ipc_importance_task *')
        return GetIPCImportantTaskSummary(iit)

def GetATMHandleSummary(handle_ptr):
    """ Convert a handle value to atm value and returns corresponding summary of its fields.
        params: handle_ptr - uint64 number stored in handle of voucher
        returns: str - summary of atm value
    """
    return "???"

def GetBankHandleSummary(handle_ptr):
    """ converts a handle value inside a voucher attribute table to bank element and returns appropriate summary.
        params: handle_ptr - uint64 number stored in handle of voucher.
        returns: str - summary of bank element
    """
    if handle_ptr == 1 :
        return "Bank task of Current task"
    elem = kern.GetValueFromAddress(handle_ptr, 'bank_element_t')
    if elem.be_type & 1 :
        ba = Cast(elem, 'struct bank_account *')
        return GetBankAccountSummary(ba)
    else:
        bt = Cast(elem, 'struct bank_task *')
        return GetBankTaskSummary(bt)

def GetBagofBitsHandleSummary(handle_ptr):
    """ Convert a handle value to bag of bits value and returns corresponding summary of its fields.
        params: handle_ptr - uint64 number stored in handle of voucher
        returns: str - summary of bag of bits element
    """
    elem = kern.GetValueFromAddress(handle_ptr, 'user_data_element_t')
    return GetBagofBitsElementSummary(elem)

@static_var('attr_managers',{1: GetATMHandleSummary, 2: GetIPCHandleSummary, 3: GetBankHandleSummary, 7: GetBagofBitsHandleSummary})
def GetHandleSummaryForKey(handle_ptr, key_num):
    """ Get a summary of handle pointer from the voucher attribute manager. 
        For example key 2 -> ipc and it puts either ipc_importance_inherit_t or ipc_important_task_t.
                    key 3 -> Bank and it puts either bank_task_t or bank_account_t.
                    key 7 -> Bag of Bits and it puts user_data_element_t in handle. So summary of it would be Bag of Bits content and refs etc.
    """
    key_num = int(key_num)
    if key_num not in GetHandleSummaryForKey.attr_managers:
        return "Unknown key %d" % key_num
    return GetHandleSummaryForKey.attr_managers[key_num](handle_ptr)


@header("{: <18s} {: <18s} {: <10s} {: <4s} {: <18s} {: <18s}".format("ivace", "value_handle", "#refs", "rel?", "maderefs", "next_layer"))
@lldb_type_summary(['ivac_entry *', 'ivac_entry_t'])
def GetIPCVoucherAttributeEntrySummary(ivace, manager_key_num = 0):
    """ Get summary for voucher attribute entry.
    """
    out_str = ""
    fmt = "{e: <#18x} {e.ivace_value: <#18x} {e.ivace_refs: <10d} {release: <4s} {made_refs: <18s} {next_layer: <18s}"
    release_str = ""
    free_str = ""
    made_refs = ""
    next_layer = ""

    if unsigned(ivace.ivace_releasing):
        release_str = "Y"
    if unsigned(ivace.ivace_free):
        free_str = 'F'
    if unsigned(ivace.ivace_layered):
        next_layer = "{: <#18x}".format(ivace.ivace_u.ivaceu_layer)
    else:
        made_refs = "{: <18d}".format(ivace.ivace_u.ivaceu_made)

    out_str += fmt.format(e=ivace, release=release_str, made_refs=made_refs, next_layer=next_layer)
    if config['verbosity'] > vHUMAN and manager_key_num > 0:
        out_str += " " + GetHandleSummaryForKey(unsigned(ivace.ivace_value), manager_key_num)
    if config['verbosity'] > vHUMAN :
        out_str += ' {: <2s} {: <4d} {: <4d}'.format(free_str, ivace.ivace_next, ivace.ivace_index)
    return out_str

@lldb_command('showivacfreelist','')
def ShowIVACFreeList(cmd_args=[], cmd_options={}):
    """ Walk the free list and print every entry in the list.
        usage: (lldb) showivacfreelist <ipc_voucher_attr_control_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError('Please provide <ipc_voucher_attr_control_t>')

    ivac = kern.GetValueFromAddress(cmd_args[0], 'ipc_voucher_attr_control_t')
    print(GetIPCVoucherAttrControlSummary.header)
    print(GetIPCVoucherAttrControlSummary(ivac))
    if unsigned(ivac.ivac_freelist) == 0:
        print("ivac table is full")
        return
    print("index " + GetIPCVoucherAttributeEntrySummary.header)
    next_free = unsigned(ivac.ivac_freelist)
    while next_free != 0:
        print("{: <5d} ".format(next_free) + GetIPCVoucherAttributeEntrySummary(addressof(ivac.ivac_table[next_free])))
        next_free = unsigned(ivac.ivac_table[next_free].ivace_next)



@header('{: <18s} {: <8s} {: <18s} {: <18s}'.format("ipc_voucher", "refs", "table", "voucher_port"))
@lldb_type_summary(['ipc_voucher *', 'ipc_voucher_t'])
def GetIPCVoucherSummary(voucher, show_entries=False):
    """ describe a voucher from its ipc_voucher * object """
    out_str = ""
    fmt = "{v: <#18x} {v.iv_refs: <8d} {table_addr: <#18x} {v.iv_port: <#18x}"
    out_str += fmt.format(v = voucher, table_addr = addressof(voucher.iv_table))
    entries_str = ''
    if show_entries or config['verbosity'] > vHUMAN:
        elems = sizeof(voucher.iv_table) // sizeof(voucher.iv_table[0])
        entries_header_str = "\n\t" + "{: <5s} {: <3s} {: <16s} {: <30s}".format("index", "key", "value_index", "manager") + " " + GetIPCVoucherAttributeEntrySummary.header
        fmt =  "{: <5d} {: <3d} {: <16d} {: <30s}"
        for i in range(elems):
            voucher_entry_index = unsigned(voucher.iv_table[i])
            if voucher_entry_index:
                s = fmt.format(i, GetVoucherManagerKeyForIndex(i), voucher_entry_index, GetVoucherAttributeManagerNameForIndex(i))
                e = GetVoucherValueHandleFromVoucherForIndex(voucher, i)
                if e is not None:
                    s += " " + GetIPCVoucherAttributeEntrySummary(addressof(e), GetVoucherManagerKeyForIndex(i) )
                if entries_header_str :
                    entries_str = entries_header_str
                    entries_header_str = ''
                entries_str += "\n\t" + s
        if not entries_header_str:
            entries_str += "\n\t"
    out_str += entries_str
    return out_str

def GetVoucherManagerKeyForIndex(idx):
    """ Returns key number for index based on global table. Will raise index error if value is incorrect
    """
    ret = iv_index_to_key(idx)
    if ret == xnudefines.MACH_VOUCHER_ATTR_KEY_NONE:
        raise IndexError("invalid voucher key")
    return ret

def GetVoucherAttributeManagerForKey(k):
    """ Return the attribute manager name for a given key 
        params: k - int key number of the manager
        return: cvalue - the attribute manager object. 
                None - if not found
    """
    idx = iv_key_to_index(k)
    if idx == xnudefines.IV_UNUSED_KEYINDEX:
        return None
    return kern.globals.ivam_global_table[idx]

def GetVoucherAttributeControllerForKey(k):
    """ Return the  attribute controller for a given key 
        params: k - int key number of the controller
        return: cvalue - the attribute controller object. 
                None - if not found
    """
    idx = iv_key_to_index(k)
    if idx == xnudefines.IV_UNUSED_KEYINDEX:
        return None
    return kern.globals.ivac_global_table[idx]


def GetVoucherAttributeManagerName(ivam):
    """ find the name of the ivam object
        param: ivam - cvalue object of type ipc_voucher_attr_manager_t
        returns: str - name of the manager
    """
    return kern.Symbolicate(unsigned(ivam))

def GetVoucherAttributeManagerNameForIndex(idx):
    """ get voucher attribute manager name for index 
        return: str - name of the attribute manager object
    """
    return GetVoucherAttributeManagerName(GetVoucherAttributeManagerForKey(GetVoucherManagerKeyForIndex(idx)))

def GetVoucherValueHandleFromVoucherForIndex(voucher, idx):
    """ traverse the voucher attrs and get value_handle in the voucher attr controls table
        params:
            voucher - cvalue object of type ipc_voucher_t
            idx - int index in the entries for which you wish to get actual handle for
        returns: cvalue object of type ivac_entry_t
                 None if no handle found.
    """
    manager_key = GetVoucherManagerKeyForIndex(idx)
    voucher_num_elems = sizeof(voucher.iv_table) // sizeof(voucher.iv_table[0])
    if idx >= voucher_num_elems:
        debuglog("idx %d is out of range max: %d" % (idx, voucher_num_elems))
        return None
    voucher_entry_value = unsigned(voucher.iv_table[idx])
    debuglog("manager_key %d" % manager_key)
    ivac = GetVoucherAttributeControllerForKey(manager_key)
    if ivac is None or addressof(ivac) == 0:
        debuglog("No voucher attribute controller for idx %d" % idx)
        return None

    ivace_table = ivac.ivac_table
    if voucher_entry_value >= unsigned(ivac.ivac_table_size):
        print("Failed to get ivace for value %d in table of size %d" % (voucher_entry_value, unsigned(ivac.ivac_table_size)))
        return None
    return ivace_table[voucher_entry_value]



@lldb_command('showallvouchers')
def ShowAllVouchers(cmd_args=[], cmd_options={}):
    """ Display a list of all vouchers in the global voucher hash table
        Usage: (lldb) showallvouchers 
    """
    print(GetIPCVoucherSummary.header)
    voucher_ty = gettype("struct ipc_voucher")
    for v in kmemory.Zone("ipc vouchers").iter_allocated(voucher_ty):
        print(GetIPCVoucherSummary(value(v.AddressOf())))

@lldb_command('showvoucher', '')
def ShowVoucher(cmd_args=[], cmd_options={}):
    """ Describe a voucher from <ipc_voucher_t> argument.
        Usage: (lldb) showvoucher <ipc_voucher_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Please provide valid argument")

    voucher = kern.GetValueFromAddress(cmd_args[0], 'ipc_voucher_t')
    print(GetIPCVoucherSummary.header)
    print(GetIPCVoucherSummary(voucher, show_entries=True))

@lldb_command('showportsendrights')
def ShowPortSendRights(cmd_args=[], cmd_options={}):
    """ Display a list of send rights across all tasks for a given port.
        Usage: (lldb) showportsendrights <ipc_port_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("no port address provided")

    port = kern.GetValueFromAddress(cmd_args[0], 'struct ipc_port *')
    if not port or port == xnudefines.MACH_PORT_DEAD:
        return

    return FindPortRights(cmd_args=[unsigned(port)], cmd_options={'-R':'S'})


@lldb_command('showtasksuspenders')
def ShowTaskSuspenders(cmd_args=[], cmd_options={}):
    """ Display the tasks and send rights that are holding a target task suspended.
        Usage: (lldb) showtasksuspenders <task_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("no task address provided")

    task = kern.GetValueFromAddress(cmd_args[0], 'task_t')

    if task.suspend_count == 0:
        print("task {:#x} ({:s}) is not suspended".format(unsigned(task), GetProcNameForTask(task)))
        return

    # If the task has been suspended by the kernel (potentially by
    # kperf, using task_suspend_internal) or a client of task_suspend2
    # that does not convert its task suspension token to a port using
    # convert_task_suspension_token_to_port, then it's impossible to determine
    # which task did the suspension.
    port = task.itk_resume
    if task.pidsuspended:
        print("task {:#x} ({:s}) has been `pid_suspend`ed. (Probably runningboardd's fault. Go look at the syslog for \"Suspending task.\")".format(unsigned(task), GetProcNameForTask(task)))
        return
    elif not port:
        print("task {:#x} ({:s}) is suspended but no resume port exists".format(unsigned(task), GetProcNameForTask(task)))
        return

    return FindPortRights(cmd_args=[unsigned(port)], cmd_options={'-R':'S'})


# Macro: showmqueue:
@lldb_command('showmqueue', fancy=True)
def ShowMQueue(cmd_args=None, cmd_options={}, O=None):
    """ Routine that lists details about a given mqueue.
        An mqueue is directly tied to a mach port, so it just shows the details of that port.
        Syntax: (lldb) showmqueue <address>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Missing mqueue argument")

    space = 0
    mqueue = kern.GetValueFromAddress(cmd_args[0], 'struct ipc_mqueue *')
    portoff = getfieldoffset('struct ipc_port', 'ip_messages')
    port = unsigned(ArgumentStringToInt(cmd_args[0])) - unsigned(portoff)
    obj = kern.GetValueFromAddress(port, 'struct ipc_object *')
    ShowPortOrPset(obj, O=O)
# EndMacro: showmqueue
