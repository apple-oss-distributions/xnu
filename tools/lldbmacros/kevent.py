from xnu import *
from workqueue import GetWorkqueueThreadRequestSummary

import kmemory

def IterateProcKqueues(proc):
    """ Iterate through all kqueues in the given process

        params:
            proc - the proc object
        returns: nothing, this is meant to be used as a generator function
            kq - yields each kqueue in the process
    """
    for kqf in IterateProcKqfiles(proc):
        yield cast(kqf, 'struct kqueue *')
    if int((fd_wqkqueue := proc.p_fd.fd_wqkqueue)) != 0:
        yield cast(fd_wqkqueue, 'struct kqueue *')
    for kqwl in IterateProcKqworkloops(proc):
        yield cast(kqwl, 'struct kqueue *')

def IterateProcKqfiles(proc):
    """ Iterate through all kqfiles in the given process

        params:
            proc - the proc object
        returns: nothing, this is meant to be used as a generator function
            kqf - yields each kqfile in the process
    """
    filetype_KQUEUE = 5

    proc_filedesc = addressof(proc.p_fd)
    proc_ofiles = proc_filedesc.fd_ofiles
    queues = list()

    if unsigned(proc_ofiles) == 0:
        return

    for fd in range(0, unsigned(proc_filedesc.fd_afterlast)):
        fd_fileproc = proc_ofiles[fd]
        if unsigned(fd_fileproc) != 0:
            # proc_fd_flags = fd_fileproc.fp_flags
            proc_fd_fglob = fd_fileproc.fp_glob
            proc_fd_ftype = unsigned(proc_fd_fglob.fg_ops.fo_type)
            if proc_fd_ftype == xnudefines.DTYPE_KQUEUE:
                proc_fd_fglob_fg_data = Cast(proc_fd_fglob.fg_data, 'void *')
                yield Cast(proc_fd_fglob_fg_data, 'struct kqfile *')

def IterateProcKqworkloops(proc):
    """ Iterate through all kqworkloops in the given process

        params:
            proc - the proc object
        returns: nothing, this is meant to be used as a generator function
            kqwl - yields each kqworkloop in the process
    """
    proc_filedesc = addressof(proc.p_fd)
    proc_fd_kqhash = proc_filedesc.fd_kqhash
    if int(proc_fd_kqhash) == 0:
        return

    hash_mask = proc_filedesc.fd_kqhashmask
    for i in range(hash_mask + 1):
        for kqwl in IterateListEntry(proc_fd_kqhash[i], 'kqwl_hashlink'):
            yield kqwl

def IterateAllKqueues():
    """ Iterate through all kqueues in the system

        returns: nothing, this is meant to be used as a generator function
            kq - yields each kqueue in the system
    """
    for t in kern.tasks:
        proc = GetProcFromTask(t)
        if proc is None:
            continue
        for kq in IterateProcKqueues(proc):
            yield kq

def IterateProcKnotes(proc):
    """ Iterate through all knotes in the given process

        params:
            proc - the proc object
        returns: nothing, this is meant to be used as a generator function
            kn - yields each knote in the process
    """
    proc_filedesc = addressof(proc.p_fd)

    if int(proc.p_fd.fd_knlist) != 0:
        for i in range(proc.p_fd.fd_knlistsize):
            for kn in IterateListEntry(proc.p_fd.fd_knlist[i], 'kn_link', list_prefix='s'):
                yield kn
    if int(proc.p_fd.fd_knhash) != 0:
        for i in range(proc.p_fd.fd_knhashmask + 1):
            for kn in IterateListEntry(proc.p_fd.fd_knhash[i], 'kn_link', list_prefix='s'):
                yield kn

def GetKnoteKqueue(kn):
    """ Get the kqueue corresponding to a given knote

        params:
            kn - the knote object
        returns: kq - the kqueue corresponding to the knote
    """

    kmem = kmemory.KMem.get_shared()
    addr = kmem.kn_kq_packing.unpack(unsigned(kn.kn_kq_packed))
    return kern.CreateTypedPointerFromAddress(addr, 'struct kqueue')


@lldb_type_summary(['knote *'])
@header('{:<20s} {:<20s} {:<10s} {:<20s} {:<20s} {:<30s} {:<10} {:<10} {:<10} {:<20s}'.format('knote', 'ident', 'kev_flags', 'kqueue', 'udata', 'filtops', 'qos_req', 'qos_use', 'qos_ovr', 'status'))
def GetKnoteSummary(kn):
    """ Summarizes a knote and related information

        returns: str - summary of knote
    """
    format_string = '{o: <#020x} {o.kn_kevent.kei_ident: <#020x} {o.kn_kevent.kei_flags: <#010x} {kq_ptr: <#020x} {o.kn_kevent.kei_udata: <#020x} {ops_str: <30s} {qos_req: <10s} {qos_use: <10s} {qos_ovr: <10s} {st_str: <20s}'
    state = unsigned(kn.kn_status)
    fops_str = kern.Symbolicate(kern.globals.sysfilt_ops[unsigned(kn.kn_kevent.kei_filtid)])
    qos_index = int(kn.kn_qos_index)
    if qos_index > 6:
        qos_req = qos_index
    else:
        qos_req = int((kn.kn_kevent.kei_qos & 0x003fff00) >> 8).bit_length()
    return format_string.format(
            o=kn,
            qos_req=xnudefines.thread_qos_short_strings[qos_req],
            qos_use=xnudefines.thread_qos_short_strings[qos_index],
            qos_ovr=xnudefines.thread_qos_short_strings[int(kn.kn_qos_override)],
            st_str=GetOptionString('kn_status_t', state, 'KN_'),
            kq_ptr=int(GetKnoteKqueue(kn)),
            ops_str=fops_str)

@lldb_command('showknote', fancy=True)
def ShowKnote(cmd_args=None, cmd_options={}, O=None):
    """ Show information about a knote

        usage: showknote <struct knote *>
    """
    if cmd_args is None or len(cmd_args) == 0:
        return O.error('missing struct knote * argument')

    kn = kern.GetValueFromAddress(cmd_args[0], 'struct knote *')
    with O.table(GetKnoteSummary.header):
        print(GetKnoteSummary(kn))

def IterateKqueueKnotes(kq):
    """ Iterate through all knotes of a given kqueue

        params:
            kq - the kqueue to iterate the knotes of
        returns: nothing, this is meant to be used as a generator function
            kn - yields each knote in the kqueue
    """
    proc = kq.kq_p
    for kn in IterateProcKnotes(proc):
        if unsigned(GetKnoteKqueue(kn)) != unsigned(addressof(kq)):
            continue
        yield kn

kqueue_summary_fmt = '{ptr: <#020x} {o.kq_p: <#020x} {dyn_id: <#020x} {servicer: <#20x} {owner: <#20x} {o.kq_count: <6d} {st_str: <10s}'

def GetServicer(req):
    if req.tr_state in [4, 5]: # [ BINDING , BOUND ]
        return int(req.tr_thread)
    return 0

@lldb_type_summary(['struct kqueue *'])
@header('{: <20s} {: <20s} {: <20s} {: <20s} {: <20s} {: <6s} {: <10s}'.format('kqueue', 'process', 'dynamic_id', 'servicer', 'owner', '#evts', 'state'))
def GetKqueueSummary(kq):
    """ Summarize kqueue information

        params:
            kq - the kqueue object
        returns: str - summary of kqueue
    """
    if int(kq.kq_state) & GetEnumValue('kq_state_t', 'KQ_WORKQ'):
        return GetKqworkqSummary(cast(kq, 'struct kqworkq *'))
    elif int(kq.kq_state) & GetEnumValue('kq_state_t', 'KQ_WORKLOOP'):
        return GetKqworkloopSummary(cast(kq, 'struct kqworkloop *'))
    else:
        return GetKqfileSummary(cast(kq, 'struct kqfile *'))

@lldb_type_summary(['struct kqfile *'])
@header(GetKqueueSummary.header)
def GetKqfileSummary(kqf):
    kq = cast(kqf, 'struct kqueue *')
    state = int(kq.kq_state)
    return kqueue_summary_fmt.format(
            o=kq,
            ptr=int(kq),
            dyn_id=0,
            st_str=GetOptionString('kq_state_t', state, 'KQ_'),
            servicer=0,
            owner=0)

@lldb_command('showkqfile', fancy=True)
def ShowKqfile(cmd_args=None, cmd_options={}, O=None):
    """ Display information about a kqfile object.

        usage: showkqfile <struct kqfile *>
    """
    if len(cmd_args) < 1:
        return O.error('missing struct kqfile * argument')

    kqf = kern.GetValueFromAddress(cmd_args[0], 'kqfile *')

    with O.table(GetKqfileSummary.header):
        print(GetKqfileSummary(kqf))
    with O.table(GetKnoteSummary.header):
        for kn in IterateKqueueKnotes(kqf.kqf_kqueue):
            print(GetKnoteSummary(kn))
        for kn in IterateTAILQ_HEAD(kqf.kqf_suppressed, 'kn_tqe'):
            print(GetKnoteSummary(kn))

@lldb_type_summary(['struct kqworkq *'])
@header(GetKqueueSummary.header)
def GetKqworkqSummary(kqwq):
    """ Summarize workqueue kqueue information

        params:
            kqwq - the kqworkq object (type 'struct kqworkq')
        returns: str - summary of workqueue kqueue
    """
    return GetKqfileSummary(kqwq)

@lldb_command('showkqworkq', fancy=True)
def ShowKqworkq(cmd_args=None, cmd_options={}, O=None):
    """ Display summary and knote information about a kqworkq.

        usage: showkqworkq <struct kqworkq *>
    """
    if len(cmd_args) < 1:
        return O.error('missing struct kqworkq * argument')

    kqwq = kern.GetValueFromAddress(cmd_args[0], 'struct kqworkq *')
    kq = kqwq.kqwq_kqueue
    with O.table(GetKqueueSummary.header):
        print(GetKqworkqSummary(kqwq))

    with O.table(GetWorkqueueThreadRequestSummary.header):
        for i in range(0, 7):
            print(GetWorkqueueThreadRequestSummary(kq.kq_p, kqwq.kqwq_request[i]))

    with O.table(GetKnoteSummary.header):
        for kn in IterateKqueueKnotes(kq):
            print(GetKnoteSummary(kn))

@lldb_type_summary(['struct kqworkloop *'])
@header(GetKqueueSummary.header)
def GetKqworkloopSummary(kqwl):
    """ Summarize workloop kqueue information

        params:
            kqwl - the kqworkloop object
        returns: str - summary of workloop kqueue
    """
    kqwl_kqueue = kqwl.kqwl_kqueue
    state = int(kqwl_kqueue.kq_state)
    return kqueue_summary_fmt.format(
            ptr=int(kqwl),
            o=kqwl_kqueue,
            dyn_id=kqwl.kqwl_dynamicid,
            st_str=GetOptionString('kq_state_t', state, 'KQ_'),
            servicer=GetServicer(kqwl.kqwl_request),
            owner=int(kqwl.kqwl_owner)
            )

@lldb_command('showkqworkloop', fancy=True)
def ShowKqworkloop(cmd_args=None, cmd_options={}, O=None):
    """ Display information about a kqworkloop.

        usage: showkqworkloop <struct kqworkloop *>
    """
    if len(cmd_args) < 1:
        return O.error('missing struct kqworkloop * argument')

    kqwl = kern.GetValueFromAddress(cmd_args[0], 'struct kqworkloop *')

    with O.table(GetKqworkloopSummary.header):
        print(GetKqworkloopSummary(kqwl))

    with O.table(GetWorkqueueThreadRequestSummary.header):
        print(GetWorkqueueThreadRequestSummary(kqwl.kqwl_kqueue.kq_p, kqwl.kqwl_request))

    with O.table(GetKnoteSummary.header):
        for kn in IterateKqueueKnotes(kqwl.kqwl_kqueue):
            print(GetKnoteSummary(kn))

@lldb_command('showkqueue', fancy=True)
def ShowKqueue(cmd_args=None, cmd_options={}, O=None):
    """ Given a struct kqueue pointer, display the summary of the kqueue

        usage: showkqueue <struct kqueue *>
    """
    if cmd_args is None or len(cmd_args) == 0:
        return O.error('missing struct kqueue * argument')

    kq = kern.GetValueFromAddress(cmd_args[0], 'struct kqueue *')
    if int(kq.kq_state) & GetEnumValue('kq_state_t', 'KQ_WORKQ'):
        ShowKqworkq(cmd_args, cmd_options, O)
    elif int(kq.kq_state) & GetEnumValue('kq_state_t', 'KQ_WORKLOOP'):
        ShowKqworkloop(cmd_args, cmd_options, O)
    else:
        ShowKqfile(cmd_args, cmd_options, O)

@lldb_command('showprocworkqkqueue', fancy=True)
def ShowProcWorkqKqueue(cmd_args=None, cmd_options={}, O=None):
    """ Show the workqueue kqueue for a given process.

        usage: showprocworkqkqueue <proc_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        return O.error('missing struct proc * argument')

    proc = kern.GetValueFromAddress(cmd_args[0], 'proc_t')
    ShowKqworkq(cmd_args=[str(int(proc.p_fd.fd_wqkqueue))])

@lldb_command('showprockqueues', fancy=True)
def ShowProcKqueues(cmd_args=None, cmd_options={}, O=None):
    """ Show the kqueues for a given process.

        usage: showprockqueues <proc_t>
    """
    if cmd_args is None or len(cmd_args) == 0:
        return O.error('missing struct proc * argument')

    proc = kern.GetValueFromAddress(cmd_args[0], 'proc_t')

    with O.table(GetKqueueSummary.header):
        for kq in IterateProcKqueues(proc):
            print(GetKqueueSummary(kq))

@lldb_command('showprocknotes', fancy=True)
def ShowProcKnotes(cmd_args=None, cmd_options={}, O=None):
    """ Show the knotes for a given process.

        usage: showprocknotes <proc_t>
    """

    if cmd_args is None or len(cmd_args) == 0:
        return O.error('missing struct proc * argument')

    proc = kern.GetValueFromAddress(cmd_args[0], 'proc_t')

    with O.table(GetKnoteSummary.header):
        for kn in IterateProcKnotes(proc):
            print(GetKnoteSummary(kn))

@lldb_command('showallkqueues', fancy=True)
def ShowAllKqueues(cmd_args=None, cmd_options={}, O=None):
    """ Display a summary of all the kqueues in the system

        usage: showallkqueues
    """
    with O.table(GetKqueueSummary.header):
        for kq in IterateAllKqueues():
            print(GetKqueueSummary(kq))

@lldb_command('showkqueuecounts', fancy=True)
def ShowKqCounts(cmd_args=None, cmd_options={}, O=None):
    """ Display a count of all the kqueues in the system - lskq summary

        usage: showkqueuecounts
    """
    print ('{: <20s} {: <35s} {: <10s} {: <6s}'.format('process', 'proc_name', '#kqfiles', '#kqworkloop'))
    for t in kern.tasks:
        proc = GetProcFromTask(t)
        if proc is None:
            continue
        proc = kern.GetValueFromAddress(unsigned(proc), 'proc_t')
        kqfcount = 0
        kqwlcount = 0
        for kqf in IterateProcKqfiles(proc):
            kqfcount += 1
        for kqwl in IterateProcKqworkloops(proc):
            kqwlcount += 1
        print("{proc: <#20x} {name: <35s} {kqfile: <10d} {kqwl: <6d}".format(proc=proc,
            name=GetProcName(proc), kqfile=kqfcount, kqwl=kqwlcount))
