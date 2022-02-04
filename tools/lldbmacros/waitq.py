from xnu import *
from utils import *
from core.configuration import *

import sys

def GetWaitqStateStr(waitq):
    wq_types = {
            0: 'INV',
            1: ' TS',
            2: '  Q',
            3: 'SET'
    }
    return wq_types[int(waitq.waitq_type)]

def GetWaitqBitsStr(waitq):
    out_str = ""
    if int(waitq.waitq_interlock.nticket) != int(waitq.waitq_interlock.cticket):
        if waitq.waitq_irq:
            out_str += '!'
        else:
            out_str += '*'
    if waitq.waitq_fifo:
        out_str += 'F'
    if waitq.waitq_prepost:
        out_str += 'P'
    if waitq.waitq_irq:
        out_str += 'I'
    return out_str

def WaitqTableElemType(e):
    type = (e.wqte.lt_bits >> 29) & 0x3
    wqe_type = {
            0: 'FREE',
            1: 'ELEM',
            2: 'LINK',
            3: 'RSVD'
    }
    return wqe_type[type]

def WaitqTableElemId(e):
    return e.wqte.lt_id.id

def WaitqTableElemValid(e):
    if unsigned(e) == 0:
        return 0
    return (e.wqte.lt_bits & 0x80000000) == 0x80000000

def WaitqTableElemRefcnt(e):
    return (e.wqte.lt_bits & 0x1fffffff)

LTABLE_ID_GEN_SHIFT = 0
LTABLE_ID_GEN_BITS  = 46
LTABLE_ID_GEN_MASK  = 0x00003fffffffffff
LTABLE_ID_IDX_SHIFT = LTABLE_ID_GEN_BITS
LTABLE_ID_IDX_BITS  = 18
LTABLE_ID_IDX_MASK  = 0xffffc00000000000

def WaitqTableIdxFromId(id):
    return int((id & LTABLE_ID_IDX_MASK) >> LTABLE_ID_IDX_SHIFT)

def WaitqTableGenFromId(id):
    return (unsigned(id) & LTABLE_ID_GEN_MASK) >> LTABLE_ID_GEN_SHIFT

def GetWaitqLink(id):
    if int(id) == 0:
        return 0, "NULL link id"
    idx = WaitqTableIdxFromId(id)
    if idx >= kern.globals.g_wqlinktable.nelem:
        return 0, "Invalid waitq link table id: {:d}".format(id)
    slab_slot = idx / kern.globals.g_wqlinktable.slab_elem;
    slab = kern.globals.g_wqlinktable.table[int(slab_slot)]
    if slab == 0:
        print "Invalid waitq link table id:", str(id), " (invalid slab)"
    first_elem = Cast(slab, 'lt_elem *')
    addr = int(slab) + ((idx - first_elem.lt_id.idx) * int(kern.globals.g_wqlinktable.elem_sz))
    link = kern.GetValueFromAddress(addr, 'waitq_link *')
    gen = WaitqTableGenFromId(id)
    warn_str = ''
    if gen > 0 and link.wqte.lt_id.generation != gen:
        warn_str = "WARNING: found idx:{:d}/gen:{:d}, but requested idx:{:d}/gen:{:d}".format(link.wqte.lt_id.idx, link.wqte.lt_id.generation, idx, gen)
        link = 0
    return link, warn_str

def GetWaitqPrepost(id):
    idx = WaitqTableIdxFromId(id)
    if idx > int(kern.globals.g_prepost_table.nelem):
        warn_str = "Invalid waitq prepost table id {:s}".format(str(id))
        return 0, warn_str
    slab_slot = idx / kern.globals.g_prepost_table.slab_elem;
    slab = kern.globals.g_prepost_table.table[int(slab_slot)]
    if slab == 0:
        warn_str = "Invalid waitq prepost table id:", str(id), " (invalid slab)"
        return 0, warn_str
    first_elem = Cast(slab, 'lt_elem *')
    addr = int(slab) + ((idx - first_elem.lt_id.idx) * int(kern.globals.g_prepost_table.elem_sz))
    wqp = kern.GetValueFromAddress(addr, 'wq_prepost *')
    gen = WaitqTableGenFromId(id)
    warn_str = ''
    if gen > 0 and wqp.wqte.lt_id.generation != gen:
        warn_str = "WARNING: found idx:{:d}/gen:{:d}, but requested idx:{:d}/gen:{:d}".format(wqp.wqte.lt_id.idx, wqp.wqte.lt_id.generation, idx, gen)
        wqp = 0
    return wqp, warn_str


def GetWaitqSetidString(setid):
    idx = WaitqTableIdxFromId(setid)
    gen = WaitqTableGenFromId(setid)
    str = "{:>7d}/{:<#14x}".format(unsigned(idx), unsigned(gen))
    return str


def GetWaitqSets(waitq):
    sets = []

    if int(waitq) == 0:
        return sets

    ref = waitq.waitq_set_id
    while int(ref.wqr_value) != 0:
        if int(ref.wqr_value) & 1:
            sets.append(GetWaitqSetidString(ref.wqr_value))
            break

        link = Cast(ref.wqr_value, 'struct waitq_link *')
        sets.append(GetWaitqSetidString(link.wql_node))
        ref  = link.wql_next

    return sets

def GetFrameString(pc, compact=True):
    str = GetSourceInformationForAddress(unsigned(pc))
    if compact:
        return re.sub(r'.*0x[0-9a-f]+\s+<(\w+)( \+ 0x[0-9a-f]+)*>.*', r'\1', str, re.UNICODE)
    else:
        return re.sub(r'.*(0x[0-9a-f]+)\s+<(\w+)( \+ 0x[0-9a-f]+)*>.*', r'\2(\1)', str, re.UNICODE)

@lldb_type_summary(['waitq_link', 'waitq_link *'])
@header("{:<18s} {:<18s} {:<19s} {:<10s} {:<1s} {:<4s} {:<10s} {:<20s}".format('addr','id','idx','gen','V','type','refcnt','info'))
def GetWaitqSetidLinkSummary(link, verbose=False):
    has_stats = 0
    if not link:
        return ""
    fmt_str = "{l: <#18x} {l.wqte.lt_id.id: <#18x} {l.wqte.lt_id.idx: <7d} (->{l.wqte.lt_next_idx: <7d}) {l.wqte.lt_id.generation: <#10x} {v: <1s} {t: <4s} {rcnt: <10d} "
    if hasattr(link, 'sl_alloc_task'):
        has_stats = 1
        fmt_str += "owner:{l.sl_alloc_task: <#x}/th:{l.sl_alloc_th: <#x}\n"
        fmt_str += ' '*87
        try:
            pid = GetProcPIDForTask(link.sl_alloc_task)
        except:
            pid = unsigned(link.sl_alloc_task.audit_token.val[5])
        pidnm = ""
        if pid < 0:
            pidnm = "DEAD:{:s}".format(GetProcNameForTask(link.sl_alloc_task))
        else:
            pidnm += GetProcNameForPid(pid)
        fmt_str += "      ({:d}/{:s}), ".format(pid, pidnm)
    type = WaitqTableElemType(link)
    if type == "ELEM":
        type = "WQS"
    v = "F"
    if WaitqTableElemValid(link):
        v = "T"
    refcnt = WaitqTableElemRefcnt(link)
    out_str = fmt_str.format(l=link, v=v, t=type, rcnt=refcnt)
    if type == "WQS":
        out_str += "wqs:{0: <#18x}".format(unsigned(link.wql_set))
    elif type == "LINK":
        sID = link.wql_node
        stype = "<invalid>"
        if WaitqTableElemValid(GetWaitqLink(sID)[0]):
            stype = "WQS"
        if int(link.wql_next.wqr_value) & 1:
            nID = link.wql_next.wqr_value
            ntype = "<invalid>"
            if WaitqTableElemValid(GetWaitqLink(nID)[0]):
                ntype = "WQS"
        else:
            nID = WaitqTableElemId(Cast(link.wql_next.wqr_value, 'struct waitq_link *'))
            ntype = "LINK"
        out_str += "set:{:<#x}({:s}), next:{:<#x}({:s})".format(sID, stype, nID, ntype)
    if hasattr(link, 'sl_alloc_bt') and unsigned(link.sl_alloc_bt[0]) > 0:
        fmt_str = "\n{:s}alloc_bt({:d}):[".format(' '*87, link.sl_alloc_ts)
        f = 0
        while f < kern.globals.g_nwaitq_btframes:
            fstr = GetFrameString(link.sl_alloc_bt[f], not verbose)
            f += 1
            if f == kern.globals.g_nwaitq_btframes:
                fmt_str += "{:<s}".format(fstr)
            else:
                fmt_str += "{:<s} <- ".format(fstr)
        fmt_str += "]"
        out_str += fmt_str
    if hasattr(link, 'sl_mkvalid_bt') and unsigned(link.sl_mkvalid_bt[0]) > 0:
        fmt_str = "\n{:s}mkvalid_bt({:d}):[".format(' '*87, link.sl_mkvalid_ts)
        f = 0
        while f < kern.globals.g_nwaitq_btframes:
            fstr = GetFrameString(link.sl_mkvalid_bt[f], not verbose)
            f += 1
            if f == kern.globals.g_nwaitq_btframes:
                fmt_str += "{:<s}".format(fstr)
            else:
                fmt_str += "{:<s} <- ".format(fstr)
        fmt_str += "]"
        out_str += fmt_str
    if hasattr(link, 'sl_invalidate_bt') and unsigned(link.sl_invalidate_bt[0]) > 0:
        fmt_str = "\n{:s}invalidate_bt({:d}):[".format(' '*87, link.sl_invalidate_ts)
        f = 0
        while f < kern.globals.g_nwaitq_btframes:
            fstr = GetFrameString(link.sl_invalidate_bt[f], not verbose)
            f += 1
            if f == kern.globals.g_nwaitq_btframes:
                fmt_str += "{:<s}".format(fstr)
            else:
                fmt_str += "{:<s} <- ".format(fstr)
        fmt_str += "]"
        out_str += fmt_str
    return out_str

def PrintWaitqSetidLinkTree(link, verbose, sets, indent=87):
    if not WaitqTableElemType(link) == "LINK":
        return

    # set
    sID = link.wql_node
    sset = GetWaitqLink(nID)[0]
    stype = "<invalid>"
    if WaitqTableElemValid(sset):
        sets.append(addressof(sset.wql_set.wqset_q))
        stype = "WQS"
    lstr = "S:{:<#x}({:s})".format(sID, stype)

    # next
    if int(link.wql_next.wqr_value) & 1:
        nID = link.wql_next.wqr_value
        nset = GetWaitqLink(nID)[0]
        ntype = "<invalid>"
        if WaitqTableElemValid():
            sets.append(addressof(sset.wql_set.wqset_q))
            ntype = "WQS"
    else:
        nID = WaitqTableElemId(Cast(link.wql_next.wqr_value, 'struct waitq_link *'))
        ntype = "LINK"
    rstr = "P:{:<#x}({:s})".format(sID, stype)

    print "{:s}`->{:s}, {:s}".format(' '*indent, lstr, rstr)
    if ltype == "WQS":
        PrintWaitqSetidLinkTree(right, verbose, sets, indent + len(lstr) + 6);
    else:
        print "{:s}`->{:s}, {:s}".format(' '*indent, lstr, rstr)
        PrintWaitqSetidLinkTree(left, verbose, sets, indent + 4);
        PrintWaitqSetidLinkTree(right, verbose, sets, indent + len(lstr) + 6)
    return

# Macro: showsetidlink
@lldb_command('showsetidlink', "S:FT")
def ShowSetidLink(cmd_args=None, cmd_options={}):
    """ Print waitq_link structure summary

        Note: you can pass either a complete ID (generation + index), or
              just the index to the -S argument.

        usage: showsetidlink [-F] [-S ID] [0xaddr]
            -S {ID} : show the setid link whose ID is {ID}
            -F      : follow the chain of setid structures
                      and print a summary of each one
            -T      : print the tree of setidlinks in table format
    """
    link = 0
    followchain = 0
    showtree = 0
    verbose = False
    if config['verbosity'] > vHUMAN:
        verbose = True
    if "-T" in cmd_options:
        showtree = 1
    if "-S" in cmd_options:
        id = value(kern.GetValueFromAddress(0).GetSBValue().CreateValueFromExpression(None, '(uint64_t)'+cmd_options["-S"]))
        link, warn_str = GetWaitqLink(id)
        if not link:
            if warn_str != '':
                raise LookupError(warn_str)
            else:
                raise ArgumentError("Invalid link ID {:d}({:<#x}".format(id, id))
    if "-F" in cmd_options:
        followchain = 1
    if link == 0:
        if not cmd_args:
            raise ArgumentError("Please pass the address of a waitq_link object")
        link = kern.GetValueFromAddress(cmd_args[0], 'waitq_link *')
    if not link:
        raise ArgumentError("Invalid waitq_link {:s}".format(cmd_args[0]))

    print GetWaitqSetidLinkSummary.header
    print GetWaitqSetidLinkSummary(link, verbose)
    if followchain == 1:
        next_id = link.wqte.lt_next_idx
        max_elem = int(kern.globals.g_wqlinktable.nelem)
        if hasattr(kern.globals, 'g_lt_idx_max'):
            max_elem = unsigned(kern.globals.g_lt_idx_max)
        while link != 0 and next_id < max_elem:
            link, warn_str = GetWaitqLink(unsigned(next_id))
            if link != 0:
                print GetWaitqSetidLinkSummary(link, verbose)
                next_id = link.wqte.lt_next_idx
    if showtree == 1:
        sets = []
        print "\nLinkTree:{:<#x}({:s})".format(link.wqte.lt_id.id, WaitqTableElemType(link))
        PrintWaitqSetidLinkTree(link, verbose, sets, 9)
        if len(sets) > 0:
            print "{:d} Sets:".format(len(sets))
            for wq in sets:
                pp_str = GetWaitqPreposts(wq)
                npreposts = len(pp_str)
                nps = ""
                if npreposts > 0:
                    if npreposts > 1:
                        nps = "s: "
                    else:
                        nps = ": "
                    nps += ';'.join(pp_str)
                else:
                    nps = "s"
                print "\tWQS:{:<#x} ({:d} prepost{:s})".format(unsigned(wq),npreposts,nps)
# EndMacro: showsetidlink
@lldb_command('showwaitqlink', "S:FT")
def ShowWaitqLink(cmd_args=None, cmd_options={}):
    """ Print waitq_link structure summary
    """
    ShowSetidLink(cmd_args, cmd_options)


# Macro: showallpreposts
@lldb_command('showallpreposts', 'VQT:F:Y:')
def ShowAllPreposts(cmd_args=None, cmd_options={}):
    """ Dump / summarize all waitq prepost linkage elements

        usage: showallpreposts [-V] [-T {type}] [-Y n] [-F n] [-Q]
            -V        : only show valid / live links
            -T {type} : only display objects of type {type}
            -Y {0|1}  : only only show POST objects that are
                        valid (-Y 1) or invalid (-Y 0)
            -F n      : summarize the backtraces at frame level 'n'
            -Q        : be quiet, only summarize
    """
    opt_summary = 0
    opt_type_filt = ""
    opt_valid_only = 0
    opt_post_type = -1
    opt_bt_idx = 0
    verbose = False
    if config['verbosity'] > vHUMAN:
        verbose = True
    if "-Q" in cmd_options:
        opt_summary = 1
    if "-V" in cmd_options:
        opt_valid_only = 1
    if "-Y" in cmd_options:
        opt_post_type = unsigned(cmd_options["-Y"])
        if opt_post_type != 0 and opt_post_type != 1:
            raise ArgumentError("Invalid POST obj specifier [-Y %d] (expected 0 or 1)" % cmd_options["-Y"])
    if "-F" in cmd_options:
        opt_bt_idx = unsigned(cmd_options["-F"])
        if hasattr(kern.globals, "g_nwaitq_btframes"):
            if opt_bt_idx >= unsigned(kern.globals.g_nwaitq_btframes):
                raise ArgumentError("Invalid BT index '{:s}' max:{:d}".format(cmd_options["-F"], unsigned(kern.globals.g_nwaitq_btframes) - 1))
    if "-T" in cmd_options:
        opt_type_filt = cmd_options["-T"]
        if opt_type_filt == "FREE" or opt_type_filt == "RSVD":
            pass
        elif opt_type_filt == "POST":
            opt_type_filt = "LINK"
        elif opt_type_filt == "WQ":
            opt_type_filt = "ELEM"
        else:
            raise ArgumentError("Invalid type filter'{:s}'".format(cmd_options["-T"]))
    table = kern.globals.g_prepost_table
    nelem = int(table.nelem)
    bt_summary = {}
    nfree = 0
    ninv = 0
    nwq = 0
    npost = 0
    nrsvd = 0
    hdr_str = "Looking through {:d} objects from g_prepost_table@{:<#x}".format(nelem, addressof(kern.globals.g_prepost_table))
    if opt_type_filt != "" or opt_valid_only != 0:
        hdr_str += "\n\t`-> for "
        if opt_valid_only:
            hdr_str += "valid "
        else:
            hdr_str += "all "
        if opt_type_filt == "":
            hdr_str += "objects"
        else:
            hdr_str += "{:s} objects".format(cmd_options["-T"])
    print hdr_str
    if not opt_summary:
        print GetWaitqPrepostSummary.header
    id = 0
    while id < nelem:
        wqp = GetWaitqPrepost(id)[0]
        if wqp == 0:
            print "<<<invalid prepost:{:d}>>>".format(id)
            ninv += 1
        else:
            lt = WaitqTableElemType(wqp)
            isvalid = WaitqTableElemValid(wqp)
            should_count = 1
            if isvalid and opt_post_type > -1 and lt == "LINK":
                post_wqp = GetWaitqPrepost(wqp.wqp_post.wqp_wq_id)[0]
                post_valid = WaitqTableElemValid(post_wqp)
                if opt_post_type == 0 and post_valid: # only count _invalid_ POST objects
                    should_count = 0
                elif opt_post_type == 1 and not post_valid: # only count _valid_ POST objects
                    should_count = 0
            if should_count and (opt_type_filt == "" or opt_type_filt == lt) and ((opt_valid_only == 0 or isvalid)):
                if lt == "ELEM":
                    nwq += 1
                elif lt == "LINK":
                    npost += 1
                elif lt == "RSVD":
                    nrsvd += 1
                elif lt == "FREE":
                    nfree += 1
                else:
                    ninv += 1
                if hasattr(wqp, 'wqp_alloc_bt'):
                    pc = unsigned(wqp.wqp_alloc_bt[opt_bt_idx])
                    pc_str = str(pc)
                    if pc > 0:
                        if pc_str in bt_summary:
                            bt_summary[pc_str] += 1
                        else:
                            bt_summary[pc_str] = 1
                if not opt_summary:
                    print GetWaitqPrepostSummary(wqp)
        if verbose:
            sys.stderr.write('id: {:d}/{:d}...          \r'.format(id, nelem))
        id += 1
    nused = nwq + npost + nrsvd
    nfound = nused + nfree + ninv
    print "\nFound {:d} objects: {:d} WQ, {:d} POST, {:d} RSVD, {:d} FREE".format(nfound, nwq, npost, nrsvd, nfree)
    if (opt_type_filt == "" and opt_valid_only == 0) and (nused != table.used_elem):
        print"\tWARNING: inconsistent state! Table reports {:d}/{:d} used elem, found {:d}/{:d}".format(table.used_elem, nelem, nused, nfound)
    if len(bt_summary) > 0:
        print "Link allocation BT (frame={:d})".format(opt_bt_idx)
    for k,v in bt_summary.iteritems():
        print "\t[{:d}] from: {:s}".format(v, GetSourceInformationForAddress(unsigned(k)))
# EndMacro: showallpreposts


@lldb_type_summary(['wq_prepost', 'wq_prepost *'])
@header("{:<18s} {:<18s} {:<19s} {:<10s} {:<1s} {:<4s} {:<10s} {:<20s}".format('addr','id','idx','gen','V','type','refcnt','info'))
def GetWaitqPrepostSummary(wqp):
    if not wqp:
        return
    fmt_str = "{w: <#18x} {w.wqte.lt_id.id: <#18x} {w.wqte.lt_id.idx: <7d} (->{w.wqte.lt_next_idx: <7d}) {w.wqte.lt_id.generation: <#10x} {v: <1s} {t: <4s} {rcnt: <10d} "
    type = WaitqTableElemType(wqp)
    if type == "ELEM":
        type = "WQ"
    elif type == "LINK":
        type = "POST"
    v = "F"
    if WaitqTableElemValid(wqp):
        v = "T"
    refcnt = WaitqTableElemRefcnt(wqp)
    out_str = fmt_str.format(w=wqp, v=v, t=type, rcnt=refcnt)
    if type == "WQ":
        out_str += "wq:{0: <#18x}".format(unsigned(wqp.wqp_wq.wqp_wq_ptr))
    elif type == "POST":
        out_str += "next:{0: <#18x}, wqid:{1: <#18x}".format(wqp.wqp_post.wqp_next_id, wqp.wqp_post.wqp_wq_id)
        post_wqp = GetWaitqPrepost(wqp.wqp_post.wqp_wq_id)[0]
        if not WaitqTableElemValid(post_wqp):
            out_str += "(<invalid>)"
        else:
            if WaitqTableElemType(post_wqp) != "ELEM":
                out_str += "(!WQP_WQ?)"
            else:
                out_str += "({0: <#18x})".format(unsigned(post_wqp.wqp_wq.wqp_wq_ptr))
    return out_str


# Macro: showprepost
@lldb_command('showprepost', "P:")
def ShowPrepost(cmd_args=None, cmd_options={}):
    """ Print prepost structure summary

        Note: you can pass either a complete ID (generation + index), or
              just the index to the -P argument.

        usage: showprepost [-P ID] [0xaddr]
            -P {ID} : show prepost structure whose ID is {ID}
    """
    wqp = 0
    if "-P" in cmd_options:
        wqp, warn_str = GetWaitqPrepost(unsigned(kern.GetValueFromAddress(cmd_options["-P"], 'uint64_t *')))
        if wqp == 0:
            if warn_str != '':
                raise LookupError(warn_str)
            else:
                raise ArgumentError("Invalid prepost ID {:s}".format(cmd_options["-P"]))
    if wqp == 0:
        if not cmd_args:
            raise ArgumentError("Please pass the address of a prepost object")
        wqp = kern.GetValueFromAddress(cmd_args[0], 'wq_prepost *')
    if not wqp:
        raise ArgumentError("Invalid prepost {:s}".format(cmd_args[0]))

    print GetWaitqPrepostSummary.header
    print GetWaitqPrepostSummary(wqp)
# EndMacro: showprepost


def WaitqPrepostFromObj(wqp, head_id, inv_ok, prepost_str, pp_arr = 0, depth = 0):
    if pp_arr != 0:
        pp_arr.append(wqp)
    etype = WaitqTableElemType(wqp)
    if not WaitqTableElemValid(wqp) and not inv_ok:
        id = 0
        if wqp:
            id = wqp.wqte.lt_id.id
        prepost_str.append("{0: <#18x}:{1: <18s}".format(id, "<invalid>"))
        return
    if etype == "ELEM": # WQP_WQ
        prepost_str.append("{0: <#18x}:{1: <#18x}".format(wqp.wqte.lt_id.id, unsigned(wqp.wqp_wq.wqp_wq_ptr)))
        return

    post_wq = 0

    if etype == "LINK": # WQP_POST
        next_id = wqp.wqp_post.wqp_next_id
        post_wq = GetWaitqPrepost(wqp.wqp_post.wqp_wq_id)[0]
        if WaitqTableElemValid(post_wq):
            if WaitqTableElemType(post_wq) != "ELEM":
                prepost_str.append("{0: <#18x}:{1: <18s}".format(post_wq.wqte.lt_id.id, "<invalid post>"))
            else:
                prepost_str.append("{0: <#18x}:{1: <#18x}".format(wqp.wqte.lt_id.id, unsigned(post_wq.wqp_wq.wqp_wq_ptr)))
        if next_id > 0 and next_id != head_id:
            if depth >= 950:
                prepost_str.append("{: <37s}".format("!recursion limit!"))
                return
            WaitqPrepostFromObj(GetWaitqPrepost(next_id)[0], head_id, inv_ok, prepost_str, pp_arr, depth + 1)
    else: #  "RSVD" or "FREE":
        prepost_str.append("{0: <#18x} -> {1: <15d}".format(wqp.wqte.lt_id.id, wqp.wqte.lt_next_idx))
        next_id = wqp.wqte.lt_next_idx
        max_elem = int(kern.globals.g_prepost_table.nelem)
        if hasattr(kern.globals, 'g_lt_idx_max'):
            max_elem = unsigned(kern.globals.g_lt_idx_max)
        if next_id < max_elem:
            if depth >= 950:
                prepost_str.append("{: <37s}".format("!recursion limit!"))
                return
            WaitqPrepostFromObj(GetWaitqPrepost(next_id)[0], head_id, inv_ok, prepost_str, pp_arr, depth + 1)
    return

def GetPrepostChain(head_id, inv_ok = False, pp_arr = 0):
    pp = []
    if unsigned(head_id) == 0:
        return [ "{0: <#18x}:{1: <18s}".format(head_id, "<invalid>") ]
    if unsigned(head_id) == 0xffffffffffffffff:
        return [ "{0: <#18x}:{1: <18s}".format(head_id, "<anonymous>") ]
    wqp = GetWaitqPrepost(head_id)[0]
    if wqp != 0:
        WaitqPrepostFromObj(wqp, head_id, inv_ok, pp, pp_arr)
    else:
        return [ "{0: <#18x}:{1: <18s}".format(head_id, "<invalid>") ]
    return pp

def GetWaitqPreposts(waitq):
    if GetWaitqStateStr(waitq) != "SET":
        return []
    wqset = Cast(waitq, 'waitq_set *')
    if wqset.wqset_prepost_id == 0:
        return []
    return GetPrepostChain(wqset.wqset_prepost_id)


# Macro: showprepostchain
@lldb_command('showprepostchain', "P:")
def ShowPrepostChain(cmd_args=None, cmd_options={}):
    """ Follow a chain of preposts, printing each one.
        Note that prepost chains are circular, so this will print
        the entire chain given a single element.

        Note: you can pass either a complete ID (generation + index), or
              just the index to the -P argument.

        usage: showprepostchain [-P ID] [0xaddr]
            -P {ID} : start printing with the prepost whose ID is {ID}
    """
    wqp = 0
    if "-P" in cmd_options:
        wqp, warn_str = GetWaitqPrepost(unsigned(kern.GetValueFromAddress(cmd_options["-P"], 'uint64_t *')))
        if wqp == 0:
            if warn_str != '':
                raise LookupError(warn_str)
            else:
                raise ArgumentError("Invalid prepost ID {:s}".format(cmd_options["-P"]))
    if wqp == 0:
        if not cmd_args:
            raise ArgumentError("Please pass the address of a prepost object")
        wqp = kern.GetValueFromAddress(cmd_args[0], 'wq_prepost *')
    if not wqp:
        raise ArgumentError("Invalid prepost {:s}".format(cmd_args[0]))

    pp_arr = []
    GetPrepostChain(wqp.wqte.lt_id.id, True, pp_arr)
    pp_cnt = len(pp_arr)
    idx = 0
    nvalid = 0
    ninvalid = 0
    print GetWaitqPrepostSummary.header
    while idx < pp_cnt:
        print GetWaitqPrepostSummary(pp_arr[idx])
        if pp_arr[idx] != 0:
            type = WaitqTableElemType(pp_arr[idx])
            if type == "LINK":
                post_wqp = GetWaitqPrepost(pp_arr[idx].wqp_post.wqp_wq_id)[0]
                if not WaitqTableElemValid(post_wqp):
                    ninvalid += 1
                else:
                    nvalid += 1
            else:
                nvalid += 1
        idx += 1
    print "%s" % '-'*86
    print "Total: {:d} ({:d} valid, {:d} invalid)".format(len(pp_arr), nvalid, ninvalid)
# EndMacro: showprepostchain


@lldb_type_summary(['waitq', 'waitq *'])
@header("{: <16s} {: <3s} {: <4s} {: <17s} {: <18s} {: <18s} {: <37s} {: <22s} {: <10s}".format('waitq', 'typ', 'bits', 'evtmask', 'setid', 'wq_wqp', 'preposts', 'member_of', 'threads'))
def GetWaitqSummary(waitq):
    fmt_str = "{q: <16x} {state: <3s} {bits: <4s} {q.waitq_eventmask: <#17x} {setid: <#18x} {q.waitq_prepost_id: <#18x}"
    th_str = []
    if waitq.waitq_queue.next and waitq.waitq_queue.prev:
        for thread in IterateLinkageChain(addressof(waitq.waitq_queue), 'thread *', 'wait_links'):
            th_str.append("{: <18s} e:{: <#18x}".format(hex(thread), thread.wait_event))
    else:
        th_str.append("{: <39s}".format('<invalid (NULL) queue>'))
    th_cnt = len(th_str)
    set_str = GetWaitqSets(waitq)
    set_cnt = len(set_str)
    pp_str = GetWaitqPreposts(waitq)
    pp_cnt = len(pp_str)
    last_str = ''
    idx = 0;
    while idx < pp_cnt or idx < set_cnt or idx < th_cnt:
        p = ""
        s = ""
        t = ""
        if idx < pp_cnt:
            p = pp_str[idx]
        if idx < set_cnt:
            s = set_str[idx]
        if idx < th_cnt:
            t = th_str[idx]
        if idx == 0:
            last_str += "{0: <37s} {1: <22s} {2: <39s}".format(p, s, t)
        else:
            last_str += "\n{0: <80s} {1: <37s} {2: <22s} {3: <39s}".format('', p, s, t)
        idx += 1
    if pp_cnt > 0 or set_cnt > 0 or th_cnt > 0:
        last_str += "\n{:<80s} {: <37s} {: <22s} {: <39s}".format('', '-'*37, '-'*20, '-'*39)
        last_str += "\n{0: <80s} {1: <37d} {2: <22d} {3: <39d}".format('', pp_cnt, set_cnt, th_cnt)

    state = GetWaitqStateStr(waitq)
    setid = 0
    if state == "SET":
        setid = Cast(waitq, 'waitq_set *').wqset_id
    out_str = fmt_str.format(q=waitq, state=state, bits=GetWaitqBitsStr(waitq), setid=setid)
    out_str += last_str
    return out_str

# Macro: showwaitq
@lldb_command('showwaitq', "P:S:")
def ShowWaitq(cmd_args=None, cmd_options={}):
    """ Print waitq structure summary.
        Lookup the waitq either by address, by Set ID, or indirectly
        through a prepost object that points to the waitq.

        Note: you can pass either a complete ID (generation + index), or
              just the index to the -P and -S arguments.

        usage: showwaitq [-P PrePostID] [-S SetID] [0xaddr]
            -P {ID}  : prepost ID that points to a waitq
            -S {ID}  : waitq_set ID
    """
    waitq = 0
    if "-P" in cmd_options:
        wqp, warn_str = GetWaitqPrepost(unsigned(kern.GetValueFromAddress(cmd_options["-P"], 'uint64_t *')))
        if wqp == 0:
            if warn_str:
                raise LookupError(warn_str)
            else:
                raise ArgumentError("Invalid prepost ID {:s}".format(cmd_options["-P"]))
        if WaitqTableElemType(wqp) != "ELEM":
            raise ArgumentError("Prepost ID {:s} points to a WQP_POST object, not a WQP_WQ!".format(cmd_options["-P"]))
        waitq = wqp.wqp_wq.wqp_wq_ptr
    if "-S" in cmd_options:
        if waitq:
            raise ArgumentError("Please pass only one of '-S' or '-P'!")
        link, warn_str = GetWaitqLink(unsigned(kern.GetValueFromAddress(cmd_options["-S"],'uint64_t *')))
        if not link:
            if warn_str != '':
                raise LookupError(warn_str)
            else:
                raise ArgumentError("Invalid link ID {:s}".format(cmd_options["-S"]))
        if WaitqTableElemType(link) != "ELEM":
            raise ArgumentError("Link ID {:s} points to a SLT_LINK object, not an SLT_WQS!".format(cmd_options["-S"]))
        waitq = addressof(link.wql_set.wqset_q)

    if not waitq and not cmd_args:
        raise ArgumentError("Please pass the address of a waitq!")
    if not waitq:
        waitq = kern.GetValueFromAddress(cmd_args[0], 'waitq *')
    if not waitq:
        raise ("Unknown arguments: %r %r" % (cmd_args, cmd_options))
    print GetWaitqSummary.header
    print GetWaitqSummary(waitq)
# EndMacro: showwaitq


# Macro: showglobalwaitqs
@lldb_command('showglobalwaitqs')
def ShowGlobalWaitqs(cmd_args=None):
    """ Summarize global waitq usage
    """
    global kern
    q = 0

    print "Global waitq objects"
    print GetWaitqSummary.header

    while q < kern.globals.g_num_waitqs:
        print GetWaitqSummary(addressof(kern.globals.global_waitqs[q]))
        q = q + 1
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
        print "No waitq stats support (use DEVELOPMENT kernel)!"
        return

    print "Global waitq stats"
    print "{0: <18s} {1: <8s} {2: <8s} {3: <8s} {4: <8s} {5: <8s} {6: <32s}".format('waitq', '#waits', '#wakes', '#diff', '#fails', '#clears', 'backtraces')

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

        print fmt_str.format(q=addressof(waitq), stats=stats, diff=diff, bt_str=bt_str)
        q = q + 1
# EndMacro: showglobalqstats
