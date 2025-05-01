"""Test all LLDB macros using LLDB session.

Usages:
    1. pytest - `xcrun --sdk macosx.internal pytest --disable-warnings -v tools/lldbmacros/tests/integration_smoke/test_lldb_macros [--remote-gdb 127.0.0.1:8000]`.
    2. module - `xcrun --sdk macosx.internal python tools/lldbmacros/tests/integration_smoke/test_lldb_macros [127.0.0.1:8000]`.
    3. macros within an existing LLDB session -
        * `xcrun --sdk macosx.internal lldb [-c coredump file]` (coredumps are supported as well, see lldb command for details.
        * `command script import command script import tools/lldbmacros/tests/integration_smoke/test_lldb_macros.py`
        * If you need a `gdb-remote`, do `gdb [ip=127.0.0.1:]<port>` (the port is usually 8000).
        * `macro_exec [macro1] [macro2] [...]`.

TODO: extend the integration tests to actually validate correctness.
"""
import contextlib
import functools
import os.path
import re
import signal
import sys
import threading
import typing

import pytest
import lldb

from lldb_session import AtDeskLLDBGdbSession


def _get_task(session: AtDeskLLDBGdbSession, name: str) -> str:
    return session.exec(f"showtask -F {name}").split('\n')[2].split()[0]


_get_init_task = functools.partial(_get_task, 'init')


def _arbitrary_task(session: AtDeskLLDBGdbSession) -> str:
    return session.exec("showalltasks").split('\n')[2].split()[0]


def _arbitrary_proc(session: AtDeskLLDBGdbSession, pid: int = 0) -> str:
    return session.exec(f"showpid {pid}").split('\n')[1].split()[5]


def _arbitrary_thread(session: AtDeskLLDBGdbSession, task_name: str = 'init') -> str:
    return session.exec(f"showtaskthreads -F {task_name}").split('\n')[3].strip().split()[0]


def _arbitrary_kext(session: AtDeskLLDBGdbSession, kext_name: str = 'com.apple.BootCache') -> str:
    return re.search(r"(0XFFFFF\w+)", session.exec(f"showkextmacho {kext_name}")).group(1)


def _arbitrary_vm_line(session: AtDeskLLDBGdbSession, row: int, col: int) -> str:
    return session.exec("showallvm").split('\n')[row].strip().split()[col]


def _arbitrary_vm_map(session: AtDeskLLDBGdbSession, index: int = 1) -> str:
    return _arbitrary_vm_line(session, row=index, col=1)


def _arbitrary_vm_node(session: AtDeskLLDBGdbSession) -> str:
    return session.exec("showallvnodes").stdout.readlines(4)[1].strip().split()[0]


def __arbitrary_ipc_line(session: AtDeskLLDBGdbSession, index: int) -> str:
    return session.exec('showallipc').split('\n')[1].strip().split()[index]


def _arbitrary_ipc(session: AtDeskLLDBGdbSession) -> str:
    return __arbitrary_ipc_line(session, index=2)


def _arbitrary_mbuf(session: AtDeskLLDBGdbSession) -> str:
    return session.exec('mbuf_showactive').split('\n')[3].strip().split()[0]


def _arbitrary_proc_channel(session: AtDeskLLDBGdbSession, task_name: str = 'apsd') -> str:
    proc_id = session.exec(f'showtask -F {task_name}').split('\n')[1].split()[6]
    return session.exec(f'showprocchannels {proc_id}').split('\n')[1].split()[0]


MACROS = [
    "kgmhelp",
    ("showraw", "showversion"),  # TODO: find a better one.
    ("xnudebug", "reload memory"),
    "showversion",
    "paniclog",
    "extpaniclog",
    "showbootargs",
    "showlldbtypesummaries",
    ("walkqueue_head", '<struct queue_entry *> "thread *" "task_threads"'),  # ?
    ("walklist_entry", '<struct proc *> "struct proc *" "p_sibling"'),  # ?
    "iotrace",
    "ttrace",
    "showsysctls",
    "showexperiments",
    "allproc",
    "zombproc",
    "zombtasks",
    "zombstacks",
    ("showcoalitioninfo", lambda session: session.exec("showallcoalitions").split('\n')[0].split()[0]),
    "showallcoalitions",
    "showcurrentforegroundapps",
    "showallthreadgroups",
    ("showtaskcoalitions", "-F init"),
    ("showtask", "-F init"),
    ("showpid", "0"),
    ("showproc", _arbitrary_proc),
    ("showprocinfo",_arbitrary_proc),
    ("showprocfiles", _arbitrary_proc),
    ("showtty", lambda session: session.exec("showallttydevs").split('\n')[2].split()[0]),
    "showallttydevs",
    "dumpthread_terminate_queue",
    ("dumpcrashed_thread_queue", None, [pytest.mark.xfail(reason='fails on live-VM coredump - rdar://136215390')]),
    ("dumpcallqueue", ""),  # TODO: ?
    "showalltasklogicalwrites",
    "showalltasks",
    ("taskforpmap", ""),  # TODO: ?
    "showterminatedtasks",
    ("showtaskstacks", "-F init"),  # TODO: does not
    ("showprocrefs", _arbitrary_task),
    "showallthreads",
    "showterminatedthreads",
    ("showtaskthreads", "-F init"),
    ("showact", _arbitrary_thread),
    ("showactstack", _arbitrary_thread),
    ("switchtoact", _arbitrary_thread),
    ("switchtoregs", _arbitrary_thread),
    ("showcallchains", "init"),  # TODO: should work without `load-script-from-symbol-file true`.
    "showallstacks",
    "showcurrentstacks",
    "showcurrentthreads",
    ("fullbt", "0"),
    ("fullbtall", None, [pytest.mark.xfail(reason='rdar://136033352')]),
    "symbolicate",
    "showinitchild",
    "showproctree",
    ("showthreadfortid", _arbitrary_thread),
    ("showtaskledgers", "-F init"),
    "showalltaskledgers",
    "showprocuuidpolicytable",
    "showalltaskpolicy",
    "showallsuspendedtasks",
    "showallpte",
    "showallrefcounts",
    "showallrunnablethreads",
    "showallschedusage",
    "showprocfilessummary",
    ("workinguserstacks", _get_init_task),
    ("workingkuserlibraries", _get_init_task),
    ("showstackaftertask", "-F init"),
    ("showstackafterthread", _get_init_task),
    ("showkextmacho", "com.apple.BootCache"),
    ("showkmodaddr", _arbitrary_kext),
    "showallkmods",
    "showallknownkmods",
    ("addkext", "-N com.apple.BootCache"),
    ("addkextaddr", _arbitrary_kext),
    ("showzpcpu", ""),  # TODO: ?
    "memstats",
    "showpgz",
    ("whatis", _arbitrary_kext),
    "showzcache",
    "zprint",
    "showkalloctypes",
    "showzchunks",
    "showallzchunks",
    "showbtref",
    "_showbtlibrary",
    "showbtlog",
    "showbtlogrecords",
    "zstack_showzonesbeinglogged",
    "zstack",
    "zstack_inorder",
    "zstack_findleak",
    "zstack_findelem",
    "zstack_findtop",
    ("showpcpu", ""),  # TODO: ?
    "showioalloc",
    "showselectmem",
    ("showtaskvme", _arbitrary_task),
    "showallvm",
    ("showtaskvm", functools.partial(_arbitrary_vm_line, row=1, col=0)),
    "showallvmstats",
    ("showmap", _arbitrary_vm_map),
    ("showmapvme", _arbitrary_vm_map),
    ("showrangevme", "-N 1"),
    "showvmtagbtlog",
    ("showmapranges", _arbitrary_vm_map, [pytest.mark.xfail(reason='rdar://136137832')]),
    ("showmapwired", _arbitrary_vm_map),
    "showallmounts",
    "showvnodepath",
    ("showvnodedev", ""),  # TODO: session.exec("showallvnodes").stdout.readlines(4)[1].strip().split()[0], you need to cancel it in the middle.
    ("showvnodelocks", ""),  # TODO: session.exec("showallvnodes").stdout.readlines(4)[1].strip().split()[0], you need to cancel it in the middle.
    ("showproclocks", ""),  # TODO: session.exec("showallvnodes").stdout.readlines(4)[1].strip().split()[0], you need to cancel it in the middle.
    "showvnode",
    "showvolvnodes",
    "showvolbusyvnodes",
    "print_vnode",
    "showworkqvnodes",
    "shownewvnodes",
    "showprocvnodes",
    "showallprocvnodes",
    ("showlock", ""),  # TODO: ?
    ("showthreadrwlck", ""),  # TODO: thread?
    "showallrwlckheld",
    ("tryfindrwlckholders", _arbitrary_thread),
    ("getthreadfromctid", ""),  # TODO: ctid?
    ("getturnstilefromctsid", ""),  # TODO: ctid?
    ("showkernapfsreflock", ""),  # TODO: kern_apfs_reflock_t?
    "showbootermemorymap",
    "show_all_purgeable_objects",
    "show_all_purgeable_nonvolatile_objects",
    "show_all_purgeable_volatile_objects",
    ("showmapcopyvme", _arbitrary_vm_map, [pytest.mark.xfail(reason='rdar://136137832')]),
    ("showmaptpro", ""),  # TODO: vm_map?
    ("showvmpage", ""),  # TODO: vm_page?
    ("showvmobject", "kernel_object_default"),
    "showallvmobjects",
    "showvmtags",
    ("showtaskloadinfo", _arbitrary_task),
    ("vmpagelookup", "kernel_object_default 0"),
    ("vmpage_get_phys_page", "<vm_page_t>"),
    ("vmpage_from_phys_page", "<ppnum_t>"),
    "vmpage_unpack_ptr",
    ("calcvmpagehash", "kernel_object_default 0"),
    ("showallocatedzoneelement", "<address of zone>"),  # TODO: ?
    ("scan_vm_pages", '-A -N 1'),
    ("vmobjectwalkpages", "kernel_object_default"),
    "show_all_apple_protect_pagers",
    ("show_apple_protect_pager", lambda session: session.exec('show_all_apple_protect_pagers').split('\n')[1].strip().split()[0]),  # no protected pager :\
    "show_all_shared_region_pagers",
    ("show_shared_region_pager", lambda session: session.exec('show_all_shared_region_pagers').split('\n')[2].strip().split()[1]),
    ("show_all_dyld_pagers", None, [pytest.mark.xfail(reason='rdar://139146013')]),
    ("show_dyld_pager", lambda session: session.exec('show_all_dyld_pagers').split('\n')[2].strip().split()[1]),
    "show_console_ring",
    "showjetsamsnapshot",
    ("showjetsamband", "0"),
    "showvnodecleanblk",
    "showvnodedirtyblk",
    ("vm_page_lookup_in_map", "<map> <vaddr>"),  # TODO: ?
    ("vm_page_lookup_in_object", "<object> <offset>"),  # TODO: ?
    ("vm_page_lookup_in_compressor_pager", "<pager> <offset>"),  # TODO: ?
    ("vm_page_lookup_in_compressor", "<slot>"),  # TODO: ?

    # vm_pageout.py
    "showvmpageoutqueues",
    "showvmpageoutstats",
    "showvmpageouthistory",

    # taskinfo.py
    'showmemorystatus',
    ('showtasksuspendsources', _arbitrary_task),
    ('showtasksuspendstats', _arbitrary_task),

    # TODO: understand why it works only on live VMs, in the meantime moved to TOO_LONG.
    # "show_all_vm_named_entries",
    # ("show_vm_named_entry", lambda session: session.exec('show_all_vm_named_entries').split('\n')[4].strip().split()[0]),

    ("showmaprb", "<vm_map>"),  # TODO: ?
    "show_all_owned_objects",
    ("show_task_owned_objects", lambda session: session.exec('show_all_owned_objects').split('\n')[3].split()[0]),
    "showdeviceinfo",
    "showdiagmemthresholds",
    ("showbankaccountstopay", lambda session: session.exec('showallbanktasklist').split('\n')[1].strip().split()[0]),
    ("showbankaccountstocharge", lambda session: session.exec('showallbanktasklist').split('\n')[1].strip().split()[0]),
    "showallbanktasklist",
    "showallbankaccountlist",
    "showwaitq",
    "showglobalwaitqs",
    "showglobalqstats",
    ("sendcore", "127.0.0.1"),  # TODO: reconsider using generic kdumpd server.
    ("sendsyslog", "127.0.0.1"),  # TODO: reconsider using generic kdumpd server.
    ("sendpaniclog", "127.0.0.1"),  # TODO: reconsider using generic kdumpd server.
    "disablecore",
    "resume_on",
    "resume_off",
    "getdumpinfo",
    ("kdp-reenter", "0"),
    "kdp-reboot",
    ("setdumpinfo", '"" "" "" 0'),  # do not change anything.
    "kdpmode",
    "showallclasses",
    ("showobject", "<OSOObject *>"),  # TODO: ?
    ("dumpobject", "<OSOObject *>"),  # TODO: same as `showobject`.
    ("setregistryplane", "0"),
    ("showregistryentry", lambda session: re.search(r'<object (0x[0-9a-f]+),', session.exec('showregistry').split('\n')[3].strip()).group(1)),
    "showregistry",
    ("findregistryentry", "VMAC400AP"),  # TODO: reconsider, might change between VM and non-VM.
    ("findregistryentries", "AppleHWAccess"),
    ("findregistryprop", lambda session: f"{re.search(r'<object (0x[0-9a-f]+),', session.exec('findregistryentries AppleHWAccess')).group(1)} IOSleepSupported"),
    ("readioport8", "0"),
    ("readioport16", "0"),
    ("readioport32", "0"),
    ("writeioport8", "0 0"),
    ("writeioport16", "0 0"),
    ("writeioport32", "0 0"),
    ("showioservicepm", "<IOServicePM *>"),  # TODO: ?
    ("showiopmqueues", None, [pytest.mark.xfail(reason='rdar://136151068')]),
    ("showiopminterest", "<IOService *>"),  # TODO: ?
    "showinterruptvectors",
    ("showiokitclasshierarchy", "<class?>"),  # TODO: ?
    "showinterruptcounts",
    "showinterruptstats",
    "showpreoslog",
    ("showeventsources", "<IOWorkLoop *>"),  # TODO: ?
    "showcarveouts",
    ("showipc", _arbitrary_ipc),
    ("showtaskipc", _arbitrary_task),
    "showallipc",
    "showipcsummary",
    ("showrights", _arbitrary_ipc),
    ("showtaskrights", functools.partial(__arbitrary_ipc_line, index=0)),
    ("countallvouchers", None, [pytest.mark.xfail(reason='rdar://136138236')]),
    ("showtaskrightsbt", functools.partial(__arbitrary_ipc_line, index=0)),
    ("findportrights", "<ipc_port_t *>"),  # TODO: ?
    "showpipestats",
    ("showtaskbusyports", _arbitrary_task),
    ("findkobjectport", "<kobject-addr>"),  # TODO: ?
    ("showtaskbusypsets", _arbitrary_task),
    "showallbusypsets",
    "showallpsets",
    ("showbusyportsummary", None, [pytest.mark.xfail(reason='rdar://136138456')]),
    ("showport", lambda session: session.exec('showallports').split('\n')[1].split()[0]),
    ("showpset", lambda session: session.exec('showallpsets').split('\n')[1].split()[0]),
    ("showkmsg", "<ipc_kmsg_t"),  # TODO: ?
    "showalliits",
    ("showallimportancetasks", None, [pytest.mark.xfail(reason='fails on MTE enabled machines -> rdar://136151386')]),
    ("showipcimportance", lambda session: session.exec('showallimportancetasks').split('\n')[1].strip().split()[0]),
    ("showivac", lambda session: session.exec('showglobalvouchertable').split('\n')[1].strip().split()[2]),
    "showglobalvouchertable",
    ("showivacfreelist", lambda session: session.exec('showglobalvouchertable').split('\n')[1].strip().split()[2]),
    "showallvouchers",
    ("showvoucher", lambda session: session.exec('showallvouchers').split('\n')[1].strip().split()[0]),
    ("showtasksuspenders", _arbitrary_task),  # TODO: find a way to get a suspend task.
    ("showmqueue", "<struct ipc_mqueue *>"),  # TODO: ?
    ("readphys", "1 1337"),
    ("writephys", "1 1337 0"),
    ("pmap_walk", "<pmap_t> <virtual offset>"),  # TODO: ?
    ("ttep_walk", "<root_ttep> <virtual offset>"),  # TODO: ?
    ("decode_tte", "1 1"),
    ("pv_walk", ""),  # TODO?
    ("kvtophys", "<kernel virtual address>"),  # TODO: ?
    ("phystokv", "0"),  # TODO: ?
    ("phystofte", "<physical address>"),  # TODO: ?
    ("showpte", "<pte_va>"),  # TODO: ?
    ("pv_check", "<pte>/<physical address>"),  # TODO: ?
    ("pmapsforledger", "0"),
    ("pmappaindex", "<pai>/<physical address>"),  # TODO: ?
    "mbuf_stat",
    "mbuf_decode",
    ("mbuf_dumpdata", _arbitrary_mbuf),
    ("mbuf_walkpkt", _arbitrary_mbuf),
    ("mbuf_walk", _arbitrary_mbuf),
    ("mbuf_buf2slab", _arbitrary_mbuf),
    ("mbuf_buf2mca", _arbitrary_mbuf),
    ("mbuf_slabs", lambda session: session.exec('mbuf_slabstbl').split('\n')[3].strip().split()[0]),
    "mbuf_slabstbl",
    "mbuf_walk_slabs",
    ("mbuf_show_m_flags", _arbitrary_mbuf),
    ("mbuf_showpktcrumbs", _arbitrary_mbuf),
    "mbuf_showactive",
    "mbuf_showinactive",
    "mbuf_show_type_summary",
    "mbuf_showmca",
    "mbuf_showall",
    ("mbuf_countchain", _arbitrary_mbuf),
    "mbuf_topleak",
    "mbuf_largefailures",
    ("mbuf_traceleak", "<mtrace *>"),  # TODO: ?
    ("mcache_walkobj", "<mcache_obj_t *>"),  # TODO: ?
    "mcache_stat",
    "mcache_showcache",
    "mbuf_wdlog",
    ("net_get_always_on_pktap", None, [pytest.mark.xfail(reason='fails on live vm coredump - rdar://136270822')]),
    "ifconfig_dlil",
    "showifaddrs",
    "ifconfig",
    "showifnets",
    "showdetachingifnets",
    "showorderedifnets",
    "showifmultiaddrs",
    "showinmultiaddrs",
    "showin6multiaddrs",
    "showsocket",
    "showprocsockets",
    "showallprocsockets",
    "show_rt_inet",
    "show_rt_inet6",
    "rtentry_showdbg",
    "inm_showdbg",
    "ifma_showdbg",
    "ifpref_showdbg",
    "ndpr_showdbg",
    "nddr_showdbg",
    "imo_showdbg",
    "im6o_showdbg",
    "rtentry_trash",
    ("show_rtentry", "<rtentry *>"),  # TODO: ?
    "inm_trash",
    "in6m_trash",
    "ifma_trash",
    "show_socket_sb_mbuf_usage",
    ("mbuf_list_usage_summary", "<struct mbuf *>"),  # TODO: ?
    "show_kern_event_pcbinfo",
    "show_kern_control_pcbinfo",
    "show_unix_domain_pcbinfo",
    "show_tcp_pcbinfo",
    "show_udp_pcbinfo",
    "show_rip_pcbinfo",
    "show_mptcp_pcbinfo",
    "show_domains",
    ("tcp_count_rxt_segments", "<tcpcb *>"),  # TODO: ?
    ("tcp_walk_rxt_segments", "<tcpcb *>"),  # TODO: ?
    ("showprocchannels", functools.partial(__arbitrary_ipc_line, index=5)),
    ("showchannelrings", _arbitrary_proc_channel),
    "showskmemcache",
    "showskmemslab",
    "showskmemarena",
    "showskmemregions",
    "showskmemregion",
    "showchannelupphash",
    "shownetns",
    "showallnetnstokens",
    "shownetnstokens",
    "shownexuschannels",
    ("showprocnecp", "<proc_t>"),  # TODO: ?
    "shownexuses",
    "showflowswitches",
    ("showcuckoohashtable", "<struct cuckoo_hashtable *>"),  # TODO: ?
    "showprotons",
    ("showthreaduserstack", "<thread_ptr>"),  # TODO: ?
    ("printuserdata", " <task_t> 0 b"),  # TODO: ?
    ("showtaskuserargs", "<task_t>"),  # TODO: ?
    ("showtaskuserstacks", "-F init", [pytest.mark.xfail(reason='fails on MTE enabled machines - rdar://136151909')]),
    ("showtaskuserlibraries", "<task_t>"),  # TODO: ?
    ("showtaskuserdyldinfo", "<task_t>"),  # TODO: ?
    ("savekcdata", " <kcdata_descriptor_t>"),  # TODO: ?
    ("pci_cfg_read", "<bits=8,16,32> <bus> <device> <function> <offset>"),  # TODO: ??
    ("pci_cfg_write", "<bits=8,16,32> <bus> <device> <function> <offset> <value>"),  # TODO: ??
    ("pci_cfg_dump", "0 0 0", [pytest.mark.xfail(reason='fails on MTE enabled machines - rdar://136198241')]),
    "pci_cfg_scan",
    "showallprocrunqcount",
    "showinterrupts",
    ("showactiveinterrupts", "<AppleInterruptController *>"),  # TODO: ?
    "showirqbyipitimerratio",
    "showinterruptsourceinfo",
    "showcurrentabstime",
    ("showschedclutch", "<processor_set_t>"),  # TODO: ?
    ("showschedclutchroot", "<struct sched_clutch_root *>"),  # TODO: ?
    ("showschedclutchrootbucket", "<struct sched_clutch_root *>"),  # TODO: ?
    ("showschedclutchbucket", "<struct sched_clutch_bucket *>"),  # TODO: ?
    ("abs2nano", "1337"),
    "showschedhistory",
    ("showrunq", "<struct run_queue *>"),  # TODO:
    "showscheduler",
    "showallprocessors",
    ("showwqthread", lambda session: session.exec(f'showprocworkqueue {_arbitrary_proc(session, pid=1)}').strip().split('\n')[-1].strip().split()[0],
     pytest.mark.xfail(reason='rdar://136138760')),
    ("showprocworkqueue", functools.partial(_arbitrary_proc, pid=1)),
    "showallworkqueues",
    "showknote",
    "showkqfile",
    "showkqworkq",
    "showkqworkloop",
    "showkqueue",
    "showprocworkqkqueue",
    "showprockqueues",
    "showprocknotes",
    "showallkqueues",
    "showkqueuecounts",
    ("showcalloutgroup", "threads", [pytest.mark.xfail(reason='fails on MTE enabled machines - rdar://136198396')]),
    # ("showcalloutgroup", "<struct thread_call_group *>"),  # TODO: session.exec('showallcallouts').stdout.readline().strip().split()[-1][1:-1]
    ("showallcallouts", None, [pytest.mark.xfail(reason='rdar://136033401')]),
    ("recount", "task -F init"),  # TODO: consider `thread`, `coalition` and `processor`.
    "showmcastate",
    "longtermtimers",
    "processortimers",
    "showcpudata",
    "showtimerwakeupstats",
    "showrunningtimers",
    ("readmsr64", "0"),
    ("writemsr64", "0 0"),  # does not work without kdp.
    ("q_iterate", "<struct queue_entry *> '<element type>' <field name>"),  # TODO: ?
    "lbrbt",
    ("lapic_read32", "0"),  # TODO: validate on Intel 64-bit architecture.
    ("lapic_write32", "0 0"),  # TODO: validate on Intel 64-bit architecture.
    "lapic_dump",
    ("ioapic_read32", "0"),  # TODO: validate on Intel 64-bit architecture.
    ("ioapic_write32", "0 0"),  # TODO: validate on Intel 64-bit architecture.
    "ioapic_dump",
    ("showstructpacking", "showstructpacking pollfd"),
    ("showallipcimportance", None, [pytest.mark.xfail(reason='fails on MTE enabled machines -> rdar://136151386')]),
    ("showturnstile", lambda session: session.exec('showallturnstiles').split('\n')[1].strip().split()[0]),
    "showturnstilehashtable",
    "showallturnstiles",
    "showallbusyturnstiles",
    "showthreadbaseturnstiles",
    "showthreadschedturnstiles",
    "kasan",
    "showkdebugtypefilter",
    "showkdebug",
    "showktrace",
    "showkdebugtrace",
    ("savekdebugtrace", "/tmp/dtrace"),
    ("xi", ""),  # TODO: ??
    ("newbt", ""),  # TODO: ??
    "parseLR",
    ("parseLRfromfile", ""),  # TODO: ?
    "showallulocks",
    "showallntstat",
    "zonetriage",
    "zonetriage_freedelement",
    "zonetriage_memoryleak",
    ("decode_sysreg", "esr_el1 0x96000021"),
    ("showcounter", "<scalable_counter_t>"),  # TODO: ?
    ("showosrefgrp", lambda session: session.exec('showglobaltaskrefgrps').split('\n')[1].strip().split()[0]),
    ("showosrefgrphierarchy",lambda session: session.exec('showglobaltaskrefgrps').split('\n')[1].strip().split()[0]),
    "showglobaltaskrefgrps",
    ("showtaskrefgrps", "<task *>"),  # TODO: ?
    "showallworkloadconfig",   # always empty :\
    ("showworkloadconfig", lambda session: session.exec('showallworkloadconfig').split('\n')[1].strip().split()[0]),
    ("showworkloadconfigphases", lambda session: session.exec('showallworkloadconfig').split('\n')[1].strip().split()[0]),
    "showlogstream",
    "showlq",
    ("showmsgbuf", "<struct msgbuf *>"),  # TODO: ?
    "systemlog",
    "shownvram",
    "showallconclaves",
    "showexclavesresourcetable",
    ("showesynctable", "<ht_t/ht_t *>"),  # TODO: ?
]

TOO_LONG = [
    "showallcsblobs",
    "triagecsblobmemory",
    "showallvnodes",
    "showallbusyvnodes",
    "pci_cfg_dump_all",
    "check_pmaps",
    "showallmappings",  # may take up to 30 minutes!
    "showptusage",
    "show_all_vm_named_entries",
    "show_vm_named_entry",
    "showallvme",
    "vm_scan_all_pages",
    "showallrights",
    "showallbusyports",  # rdar://136138456
    "showallports",
    "countallports",  # rdar://136138236
    "showregistryprops",
    "showportsendrights",  # rdar://136138614
    "showthreadswaitingforuserserver",  # Stuck forever on some devices.
]

INTERACTIVE = [
    "beginusertaskdebugging"
]

OBSOLETE = [
    "showkerneldebugbuffercpu",
    "showkerneldebugbuffer",
    "dumprawtracefile"
]
IGNORES = TOO_LONG + INTERACTIVE + OBSOLETE



@pytest.fixture(scope='session')
def lldb_gdb_session(pytestconfig: pytest.Config) -> AtDeskLLDBGdbSession:
    if pytestconfig.getoption('--use-existing-debugger'):
        session = AtDeskLLDBGdbSession(lldb.debugger.GetCommandInterpreter())
        session.refresh()
        yield session
        return

    with AtDeskLLDBGdbSession.create(pytestconfig.getoption('--gdb-remote')) as session:
        yield session


@pytest.fixture(scope='session')
def ignores(pytestconfig: pytest.Config) -> set[str]:
    return set(IGNORES) | set(pytestconfig.getoption('--extra-ignores').split(','))


@pytest.fixture
def _skip_if_dirty(request: pytest.FixtureRequest) -> None:
    if request.session.stash.get('dirty', False):
        pytest.skip('LLDB session is "dirty", skipping.')


@pytest.fixture
def _timed_action(_skip_if_dirty: None, request: pytest.FixtureRequest) -> typing.Callable[[float], typing.ContextManager[None]]:
    def kill_session():
        request.session.stash['dirty'] = True
        os.kill(os.getpid(), signal.SIGTERM)

    @contextlib.contextmanager
    def timed_context(timeout: float) -> None:
        timed_out = False

        def fail(*_):
            nonlocal timed_out
            timed_out = True

        signal.signal(signalnum=signal.SIGTERM, handler=fail)

        timer = threading.Timer(interval=timeout, function=kill_session)
        timer.start()
        try:
            yield
        finally:
            timer.cancel()
            signal.signal(signal.SIGTERM, signal.SIG_DFL)  # unmask

            if timed_out:
                pytest.fail('The LLDB session is stuck, self-destructing.')

    return timed_context


MACROS = [(i, None, []) if isinstance(i, str) else (i if len(i) == 3 else (*i, [])) for i in MACROS]


@pytest.mark.parametrize('macro', [pytest.param(i[:-1], marks=i[-1], id=i[0]) for i in MACROS])
def test_macro_exec(_timed_action: typing.Callable[[float], typing.ContextManager[None]],
                    macro: tuple[str, typing.Optional[str], typing.Optional[list[pytest.Mark]]],
                    lldb_gdb_session: AtDeskLLDBGdbSession) -> None:
    macro, args_or_func = macro
    if hasattr(args_or_func, '__call__'):
        try:
            macro = f'{macro} {args_or_func(lldb_gdb_session)}'
        except Exception:
            pytest.skip('Unable to evaluate additional argument(s).')
    elif args_or_func is not None:
        if args_or_func == '' or '<' in args_or_func:
            pytest.skip('The test is not implemented, skipping.')
        macro = f'{macro} {args_or_func}'

    with _timed_action(timeout=120.):
        lldb_gdb_session.exec(macro)


def test_macro_coverage(lldb_gdb_session: AtDeskLLDBGdbSession, ignores: set[str]) -> None:
    stdout = lldb_gdb_session.exec('help')
    _start_after = 'Current user-defined commands:'
    _end_before = "For more information on any command, type 'help <command-name>'."
    print(f'{stdout=}')
    user_defined_macros = stdout[stdout.find(_start_after) + len(_start_after): stdout.find(_end_before)]
    print(f'{user_defined_macros}')
    macro_extractor = re.compile(r'(\w+-\w+|\w+)\s+--\s')

    covered = {i[0].split()[0]  # All subcommands are aggregated under a single command (see `help` command).
               for i in MACROS} | ignores
    macros = set()
    for line in user_defined_macros.split('\n'):
        if len(line.strip()) == 0:
            continue
        match = macro_extractor.search(line)
        if match is None:
            continue
        macros.add(match.group(1))
    print('macros', macros)
    print('covered', covered)
    # macros = {i for i in macros if not i.startswith('_')}
    assert macros == covered, f'not_covered_by_tests=`{macros - covered}`, missing_macros=`{covered - macros}`'
    # assert not_covered == []


def macro_exec(debugger, command, result, internal_dict) -> None:
    """Run tests for all LLDB macros (except for IGNORES, see above).

    Usage:
        (lldb) test_macro_exec
        -> Test all macros

        (lldb) test_macro_exec [macro_1] [macro 2] ...
        -> Test specific macro(s).
    """
    no_color = '--no-color' in command
    if no_color:
        command = command.replace('--no-color', '').strip()

    abs_file = os.path.abspath(__file__)
    abs_root = os.path.dirname(abs_file)
    os.chdir(abs_root)

    result.ret = pytest.main(
        (['--color', 'no'] if no_color else []) +
        ['--disable-warnings', '--rootdir', abs_root,
         f'--durations={len(MACROS)}',  # It is the maximal number of test cases.
         '-s' if len(command.strip()) > 0 else '-vv',
         '-k', macro_exec.__name__, abs_file, '--use-existing-debugger',
        ] + [f'{abs_file}::{test_macro_exec.__name__}[{i}]'
             # Supporting multi-word commands, e.g.: sub-command, options, anything between "" / '' / a single word.
             for i in re.split('\'(.+?)\'|"(.+?)"|(\\S+)\\s+|(\\S+)$', command)
             if i and i.strip()])


def macro_coverage(debugger, command, result, internal_dict) -> None:
    """Run the macro coverage test.

    Usage:
        (lldb) test_macro_coverage
        -> Test macro coverage (see also `IGNORES` or --extra-ignores).
    """
    abs_file = os.path.abspath(__file__)
    abs_root = os.path.dirname(abs_file)
    os.chdir(abs_root)

    result.ret = pytest.main(
        (['--color', 'no'] if '--no-color' in command else []) + [
         '--disable-warnings', '--rootdir', abs_root,
         '-v', '-k', test_macro_coverage.__name__, abs_file,
         '--use-existing-debugger', '--extra-ignores', f'hwtrace,{macro_exec.__name__},{macro_coverage.__name__}'
    ])


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(f'command script add -f {macro_exec.__module__}.{macro_exec.__name__} {macro_exec.__name__}')
    print(f'The `{macro_exec.__name__}` command has been installed and is ready to use.')

    debugger.HandleCommand(f'command script add -f {macro_coverage.__module__}.{macro_coverage.__name__} {macro_coverage.__name__}')
    print(f'The `{macro_coverage.__name__}` command has been installed and is ready to use.')


if __name__ == '__main__':
    remote_gdb = sys.argv[1]
    pytest.main(['--disable-warnings', '-v', __file__, '--gdb-remote', remote_gdb])
