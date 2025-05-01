
""" Please make sure you read the README COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file.
"""
from .cvalue import value
from . import iterators as ccol
from .caching import (
    LazyTarget,
    dyn_cached_property,
    cache_dynamically,
    cache_statically,
)
from utils import *

import lldb

class UnsupportedArchitectureError(RuntimeError):
    def __init__(self, arch, msg="Unsupported architecture"):
        self._arch = arch
        self._msg = msg
        super().__init__(msg)

    def __str__(self):
        return '%s: %s' % (self._arch, self._msg)


def IterateTAILQ_HEAD(headval, element_name, list_prefix=''):
    """ iterate over a TAILQ_HEAD in kernel. refer to bsd/sys/queue.h
        params:
            headval      - value : value object representing the head of the list
            element_name - str   :  string name of the field which holds the list links.
            list_prefix  - str   : use 's' here to iterate STAILQ_HEAD instead
        returns:
            A generator does not return. It is used for iterating.
            value : an object that is of type as headval->tqh_first. Always a pointer object
        example usage:
          list_head = kern.GetGlobalVariable('mountlist')
          for entryobj in IterateTAILQ_HEAD(list_head, 'mnt_list'):
            print GetEntrySummary(entryobj)
    """

    next_path = ".{}.{}tqe_next".format(element_name, list_prefix)
    head = headval.GetSBValue()

    return (value(e.AddressOf()) for e in ccol.iter_linked_list(
        head.Dereference() if head.TypeIsPointerType() else head,
        next_path,
        list_prefix + 'tqh_first',
    ))


def IterateLinkedList(headval, field_name):
    """ iterate over a linked list.
        This is equivalent to elt = headval; while(elt) { do_work(elt); elt = elt-><field_name>; }
        params:
            headval - value : value object representing element in the list.
            field_name - str       : name of field that holds pointer to next element
        returns: Nothing. This is used as iterable
        example usage:
            first_zone = kern.GetGlobalVariable('first_zone')
            for zone in IterateLinkedList(first_zone, 'next_zone'):
                print GetZoneSummary(zone)
    """

    head = headval.GetSBValue()

    return (value(e.AddressOf()) for e in ccol.iter_linked_list(head, field_name))


def IterateListEntry(headval, field_name, list_prefix=''):
    """ iterate over a list as defined with LIST_HEAD in bsd/sys/queue.h
        params:
            headval      - value : Value object for lh_first
            field_name   - str   : Name of the field in next element's structure
            list_prefix  - str   : use 's' here to iterate SLIST_HEAD instead
        returns:
            A generator does not return. It is used for iterating
            value  : an object thats of type (element_type) head->le_next. Always a pointer object
        example usage:
            headp = kern.globals.initproc.p_children
            for pp in IterateListEntry(headp, 'p_sibling'):
                print GetProcInfo(pp)
    """

    next_path = ".{}.{}le_next".format(field_name, list_prefix)
    head = headval.GetSBValue()

    return (value(e.AddressOf()) for e in ccol.iter_linked_list(
        head.Dereference() if head.TypeIsPointerType() else head,
        next_path,
        list_prefix + 'lh_first',
    ))


def IterateLinkageChain(queue_head, element_type, field_name):
    """ Iterate over a Linkage Chain queue in kernel of type queue_head_t. (osfmk/kern/queue.h method 1)
        This is equivalent to the qe_foreach_element() macro
        params:
            queue_head   - value       : Value object for queue_head.
            element_type - lldb.SBType : pointer type of the element which contains the queue_chain_t. Typically its structs like thread, task etc..
                         - str         : OR a string describing the type. ex. 'task *'
            field_name   - str         : Name of the field (in element) which holds a queue_chain_t
        returns:
            A generator does not return. It is used for iterating.
            value  : An object thats of type (element_type). Always a pointer object
        example usage:
            coalq = kern.GetGlobalVariable('coalitions_q')
            for coal in IterateLinkageChain(coalq, 'struct coalition *', 'coalitions'):
                print GetCoalitionInfo(coal)
    """

    if isinstance(element_type, str):
        element_type = gettype(element_type)

    head = queue_head.GetSBValue()

    return (value(e.AddressOf()) for e in ccol.iter_queue_entries(
        head.Dereference() if head.TypeIsPointerType() else head,
        element_type.GetPointeeType(),
        field_name,
    ))


def IterateCircleQueue(queue_head, element_type, field_name):
    """ iterate over a circle queue in kernel of type circle_queue_head_t. refer to osfmk/kern/circle_queue.h
        params:
            queue_head    - lldb.SBValue : Value object for queue_head.
            element_type  - lldb.SBType : a type of the element 'next' points to. Typically its structs like thread, task etc..
            field_name    - str : name of the field in target struct.
        returns:
            A generator does not return. It is used for iterating.
            SBValue  : an object thats of type (element_type) queue_head->next. Always a pointer object
    """

    if isinstance(element_type, str):
        element_type = gettype(element_type)

    head = queue_head.GetSBValue()

    return (value(e.AddressOf()) for e in ccol.iter_circle_queue(
        head.Dereference() if head.TypeIsPointerType() else head,
        element_type,
        field_name,
    ))


def IterateQueue(queue_head, element_ptr_type, element_field_name, backwards=False, unpack_ptr_fn=None):
    """ Iterate over an Element Chain queue in kernel of type queue_head_t. (osfmk/kern/queue.h method 2)
        params:
            queue_head         - value : Value object for queue_head.
            element_ptr_type   - lldb.SBType : a pointer type of the element 'next' points to. Typically its structs like thread, task etc..
                               - str         : OR a string describing the type. ex. 'task *'
            element_field_name - str : name of the field in target struct.
            backwards          - backwards : traverse the queue backwards
            unpack_ptr_fn      - function : a function ptr of signature def unpack_ptr(long v) which returns long.
        returns:
            A generator does not return. It is used for iterating.
            value  : an object thats of type (element_type) queue_head->next. Always a pointer object
        example usage:
            for page_meta in IterateQueue(kern.globals.first_zone.pages.all_free, 'struct zone_page_metadata *', 'pages'):
                print page_meta
    """

    if isinstance(element_ptr_type, str):
        element_ptr_type = gettype(element_ptr_type)

    head = queue_head.GetSBValue()

    return (value(e.AddressOf()) for e in ccol.iter_queue(
        head.Dereference() if head.TypeIsPointerType() else head,
        element_ptr_type.GetPointeeType(),
        element_field_name,
        backwards=backwards,
        unpack=unpack_ptr_fn,
    ))


def IterateRBTreeEntry(rootelt, field_name):
    """ iterate over a rbtree as defined with RB_HEAD in libkern/tree.h
            rootelt      - value : Value object for rbh_root
            field_name   - str   : Name of the field in link element's structure
        returns:
            A generator does not return. It is used for iterating
            value  : an object thats of type (element_type) head->sle_next. Always a pointer object
    """

    return (value(e.AddressOf()) for e in ccol.iter_RB_HEAD(rootelt.GetSBValue(), field_name))


def IterateSchedPriorityQueue(root, element_type, field_name):
    """ iterate over a priority queue as defined with struct priority_queue from osfmk/kern/priority_queue.h
            root         - value : Value object for the priority queue
            element_type - str   : Type of the link element
            field_name   - str   : Name of the field in link element's structure
        returns:
            A generator does not return. It is used for iterating
            value  : an object thats of type (element_type). Always a pointer object
    """

    if isinstance(element_type, str):
        element_type = gettype(element_type)

    root = root.GetSBValue()

    return (value(e.AddressOf()) for e in ccol.iter_priority_queue(
        root.Dereference() if root.TypeIsPointerType() else root,
        element_type,
        field_name,
    ))


def IterateMPSCQueue(root, element_type, field_name):
    """ iterate over an MPSC queue as defined with struct mpsc_queue_head from osfmk/kern/mpsc_queue.h
            root         - value : Value object for the mpsc queue
            element_type - str   : Type of the link element
            field_name   - str   : Name of the field in link element's structure
        returns:
            A generator does not return. It is used for iterating
            value  : an object thats of type (element_type). Always a pointer object
    """
    if isinstance(element_type, str):
        element_type = gettype(element_type)

    return (value(e.AddressOf()) for e in ccol.iter_mpsc_queue(
        root.GetSBValue(), element_type, field_name
    ))

function_counters = dict()

class KernelTarget(object):
    """ A common kernel object that provides access to kernel objects and information.
        The class holds global lists for  task, terminated_tasks, procs, zones, zombroc etc.
        It also provides a way to symbolicate an address or create a value from an address.
    """
    def __init__(self, debugger):
        """ Initialize the kernel debugging environment.
            Target properties like architecture and connectedness are lazy-evaluted.
        """

        self.symbolicator = None

        class _GlobalVariableFind(object):
            def __init__(self, kern):
                self._xnu_kernobj_12obscure12 = kern

            @cache_statically
            def __getattr__(self, name, target=None):
                v = self._xnu_kernobj_12obscure12.GetGlobalVariable(name)
                if not v.GetSBValue().IsValid():
                    # Python 2 swallows all exceptions in hasattr(). That makes it work
                    # even when global variable is not found. Python 3 has fixed the behavior
                    # and we can raise only AttributeError here to keep original behavior.
                    raise AttributeError('No such global variable by name: %s '%str(name))
                return v
            def __contains__(self, name):
                try:
                    val = self.__getattr__(name)
                    return True
                except AttributeError:
                    return False
        self.globals = _GlobalVariableFind(self)


    def _GetSymbolicator(self):
        """ Internal function: To initialize the symbolication from lldb.utils
        """
        if not self.symbolicator is None:
            return self.symbolicator

        from lldb.utils import symbolication
        symbolicator = symbolication.Symbolicator()
        symbolicator.target = LazyTarget.GetTarget()
        self.symbolicator = symbolicator
        return self.symbolicator

    def Symbolicate(self, addr):
        """ simple method to get name of function/variable from an address. this is equivalent of gdb 'output /a 0xaddress'
            params:
                addr - int : typically hex value like 0xffffff80002c0df0
            returns:
                str - '' if no symbol found else the symbol name.
            Note: this function only finds the first symbol. If you expect multiple symbol conflict please use SymbolicateFromAddress()
        """
        ret_str = ''
        syms = self.SymbolicateFromAddress(addr)
        if len(syms) > 0:
            ret_str +=syms[0].GetName()
        return ret_str

    def SymbolicateFromAddress(self, addr, fullSymbol=False):
        """ symbolicates any given address based on modules loaded in the target.
            params:
                addr - int : typically hex value like 0xffffff80002c0df0
            returns:
                [] of SBSymbol: In case we don't find anything than empty array is returned.
                      Note: a type of symbol can be figured out by gettype() function of SBSymbol.
            example usage:
                syms = kern.Symbolicate(0xffffff80002c0df0)
                for s in syms:
                  if s.GetType() == lldb.eSymbolTypeCode:
                    print "Function", s.GetName()
                  if s.GetType() == lldb.eSymbolTypeData:
                    print "Variable", s.GetName()
        """
        if type(int(1)) != type(addr):
            if str(addr).strip().find("0x") == 0 :
                addr = int(addr, 16)
            else:
                addr = int(addr)
        addr = self.StripKernelPAC(addr)
        ret_array = []
        symbolicator = self._GetSymbolicator()
        syms = symbolicator.symbolicate(addr)
        if not syms:
            return ret_array
        for s in syms:
            if fullSymbol:
                ret_array.append(s)
            else:
                ret_array.append(s.get_symbol_context().symbol)
        return ret_array

    def IsDebuggerConnected(self):
        proc_state = LazyTarget.GetProcess().state
        if proc_state == lldb.eStateInvalid : return False
        if proc_state in [lldb.eStateStopped, lldb.eStateSuspended] : return True

    @staticmethod
    @cache_statically
    def GetGlobalVariable(name, target=None):
        """ Get the value object representation for a kernel global variable
            params:
              name : str - name of the variable. ex. version
            returns: value - python object representing global variable.
            raises : Exception in case the variable is not found.
        """

        return value(target.FindGlobalVariables(name, 1).GetValueAtIndex(0))

    @cache_statically
    def PERCPU_BASE(self, cpu, target=None):
        """ Get the PERCPU base for the given cpu number
            params:
              cpu  : int - the cpu# for this variable
            returns: int - the base for PERCPU for this cpu index
        """
        if self.arch == 'x86_64':
            return unsigned(self.globals.cpu_data_ptr[cpu].cpu_pcpu_base)
        elif self.arch.startswith('arm'):
            data_entries = self.GetGlobalVariable('CpuDataEntries')
            BootCpuData = addressof(self.GetGlobalVariable('percpu_slot_cpu_data'))
            return unsigned(data_entries[cpu].cpu_data_vaddr) - unsigned(BootCpuData)

    def PERCPU_GET(self, name, cpu):
        """ Get the value object representation for a kernel percpu global variable
            params:
              name : str - name of the variable. ex. version
              cpu  : int - the cpu# for this variable
            returns: value - python object representing global variable.
            raises : Exception in case the variable is not found.
        """
        var = addressof(self.GetGlobalVariable('percpu_slot_' + name))
        var_type = var.GetSBValue().GetType().name
        addr = unsigned(var) + self.PERCPU_BASE(cpu)
        return dereference(self.GetValueFromAddress(addr, var_type))

    @cache_statically
    def GetLoadAddressForSymbol(self, name, target=None):
        """ Get the load address of a symbol in the kernel.
            params:
              name : str - name of the symbol to lookup
            returns: int - the load address as an integer. Use GetValueFromAddress to cast to a value.
            raises : LookupError - if the symbol is not found.
        """
        name = str(name)
        syms_arr = target.FindSymbols(name)
        if syms_arr.IsValid() and len(syms_arr) > 0:
            symbol = syms_arr[0].GetSymbol()
            if symbol.IsValid():
                return int(symbol.GetStartAddress().GetLoadAddress(target))

        raise LookupError("Symbol not found: " + name)

    def GetValueFromAddress(self, addr: int, type_str: str = 'void *') -> value:
        """ convert an address to a value
            params:
                addr - int : typically hex value like 0xffffff80008dc390
                type_str - str: type to cast to. Default type will be void *
            returns:
                value : a value object which has address as addr and type is type_str
        """
        sbv = self.globals.version.GetSBValue().CreateValueFromExpression(None,f"({type_str}){str(addr)}")

        wanted_type = gettype(type_str)
        if sbv.GetType() != wanted_type:
            sbv = sbv.Cast(wanted_type)

        return value(sbv)

    def CreateValueFromAddress(self, addr: int, type_str: str = 'void *') -> value:
        """ convert an address to a value, using `GetValueFromAddress()`
            params:
                addr - int : typically hex value like 0xffffff80008dc390
                type_str - str: type to cast to. Default type will be void *
            returns:
                value : a value object which has address as addr and type is type_str

            There are 2 LLDB APIs to create SBValues for data in memory - `CreateValueFromExpression()` and `CreateValueFromAddress()`.
            The former will parse an expression (like those used in an LLDB print command - `p/x *(vm_map_t)0xFOO_ADDR`).
            The latter allows telling LLDB "Give me an SBValue that interprets the data begginning at FOO address as BAR type".

            `CreateValueFromAddress()` is more performant, but can be clunkier to work with.
            However, for simple use cases it can be just as convenient as `CreateValueFromExpression()`.
            Just take heed that you probably don't want "an SBValue for a pointer to BAR type who's data is at address FOO",
            rather "an SBValue for BAR type who's data is at address FOO".
            
            Where performance matters or there's no usability tradeoff, you're encouraged to use `CreateValueFromAddress()` over `GetValueFromAddress()`.
            The poor, confusing naming is legacy :/

        """
        sbv = self.globals.version.GetSBValue().xCreateValueFromAddress(None, addr, gettype(type_str))
        return value(sbv)

    def CreateTypedPointerFromAddress(self, addr, type_str = "char"):
        """ convert a address to pointer value

            Note: This is obsolete and here as a temporary solution
                  for people to migrate to using references instead.

            params:
                addr - int : typically hex value like 0xffffff80008dc390
                type_str - str: type to cast to, must not be a pointer type.
            returns:
                value : a value object which has address as addr
                        and type is `type_str *`
        """

        target = LazyTarget.GetTarget()
        sbv    = target.xCreateValueFromAddress(None, addr, gettype(type_str))
        return value(sbv.AddressOf())


    def GetValueAsType(self, v, t):
        """ Retrieves a global variable 'v' of type 't' wrapped in a vue object.
            If 'v' is an address, creates a vue object of the appropriate type.
            If 'v' is a name, looks for the global variable and asserts its type.
            Throws:
                NameError - If 'v' cannot be found
                TypeError - If 'v' is of the wrong type
        """
        if islong(v):
            return self.GetValueFromAddress(v, t)
        else:
            var = LazyTarget.GetTarget().FindGlobalVariables(v, 1)[0]
            if not var:
                raise NameError("Failed to find global variable '{0}'".format(v))
            if var.GetTypeName() != t:
                raise TypeError("{0} must be of type '{1}', not '{2}'".format(v, t, var.GetTypeName()))
            return value(var)

    def _GetIterator(self, iter_head_name, next_element_name='next', iter_head_type=None):
        """ returns an iterator for a collection in kernel memory.
            params:
                iter_head_name - str : name of queue_head or list head variable.
                next_element_name - str : name of the element that leads to next element.
                                          for ex. in struct zone list 'next_zone' is the linking element.
            returns:
                iterable : typically used in conjunction with "for varname in iterable:"
        """
        head_element = self.GetGlobalVariable(iter_head_name)
        return head_element.GetSBValue().linked_list_iter(next_element_name)

    def TruncPage(self, addr):
        return (addr & ~(unsigned(self.GetGlobalVariable("page_size")) - 1))

    def RoundPage(self, addr):
        return trunc_page(addr + unsigned(self.GetGlobalVariable("page_size")) - 1)

    def StraddlesPage(self, addr, size):
        if size > unsigned(self.GetGlobalVariable("page_size")):
            return True
        val = ((addr + size) & (unsigned(self.GetGlobalVariable("page_size"))-1))
        return (val < size and val > 0)

    def StripUserPAC(self, addr):
        if self.arch != 'arm64e':
            return addr
        T0Sz = self.GetGlobalVariable('gT0Sz')
        return StripPAC(addr, T0Sz)

    def StripKernelPAC(self, addr):
        if self.arch != 'arm64e':
            return addr
        T1Sz = self.GetGlobalVariable('gT1Sz')
        return StripPAC(addr, T1Sz)

    PAGE_PROTECTION_TYPE_NONE = 0
    PAGE_PROTECTION_TYPE_PPL = 1
    PAGE_PROTECTION_TYPE_SPTM = 2

    def PhysToKVARM64(self, addr):
        if self.globals.page_protection_type <= self.PAGE_PROTECTION_TYPE_PPL:
            ptov_table = self.globals.ptov_table
            for i in range(0, self.globals.ptov_index):
                if (addr >= int(unsigned(ptov_table[i].pa))) and (addr < (int(unsigned(ptov_table[i].pa)) + int(unsigned(ptov_table[i].len)))):
                    return (addr - int(unsigned(ptov_table[i].pa)) + int(unsigned(ptov_table[i].va)))
        else:
            papt_table = self.globals.libsptm_papt_ranges
            page_size = self.globals.page_size
            for i in range(0, self.globals.libsptm_n_papt_ranges):
                if (addr >= int(unsigned(papt_table[i].paddr_start))) and (addr < (int(unsigned(papt_table[i].paddr_start)) + int(unsigned(papt_table[i].num_mappings) * page_size))):
                    return (addr - int(unsigned(papt_table[i].paddr_start)) + int(unsigned(papt_table[i].papt_start)))
            raise ValueError("PA {:#x} not found in physical region lookup table".format(addr))
        return (addr - unsigned(self.globals.gPhysBase) + unsigned(self.globals.gVirtBase))

    def PhysToKernelVirt(self, addr):
        if self.arch == 'x86_64':
            return (addr + unsigned(self.GetGlobalVariable('physmap_base')))
        elif self.arch.startswith('arm64'):
            return self.PhysToKVARM64(addr)
        elif self.arch.startswith('arm'):
            return (addr - unsigned(self.GetGlobalVariable("gPhysBase")) + unsigned(self.GetGlobalVariable("gVirtBase")))
        else:
            raise ValueError("PhysToVirt does not support {0}".format(self.arch))

    @cache_statically
    def GetUsecDivisor(self, target=None):
        if self.arch == 'x86_64':
            return 1000

        rtclockdata_addr = self.GetLoadAddressForSymbol('RTClockData')
        rtc = self.GetValueFromAddress(rtclockdata_addr, 'struct _rtclock_data_ *')
        return unsigned(rtc.rtc_usec_divisor)

    def GetNanotimeFromAbstime(self, abstime):
        """ convert absolute time (which is in MATUs) to nano seconds.
            Since based on architecture the conversion may differ.
            params:
                abstime - int absolute time as shown by mach_absolute_time
            returns:
                int - nanosecs of time
        """
        return (abstime * 1000) // self.GetUsecDivisor()

    @property
    @cache_statically
    def zones(self, target=None):
        za = target.chkFindFirstGlobalVariable('zone_array')
        zs = target.chkFindFirstGlobalVariable('zone_security_array')
        n  = target.chkFindFirstGlobalVariable('num_zones').xGetValueAsInteger()

        iter_za = za.chkGetChildAtIndex(0).xIterSiblings(0, n)
        iter_zs = zs.chkGetChildAtIndex(0).xIterSiblings(0, n)

        return [
            (value(next(iter_za).AddressOf()), value(next(iter_zs).AddressOf()))
            for i in range(n)
        ]

    @property
    def threads(self):
        target = LazyTarget.GetTarget()

        return (value(t.AddressOf()) for t in ccol.iter_queue(
            target.chkFindFirstGlobalVariable('threads'),
            gettype('thread'),
            'threads',
        ))

    @dyn_cached_property
    def tasks(self, target=None):
        return [value(t.AddressOf()) for t in ccol.iter_queue(
            target.chkFindFirstGlobalVariable('tasks'),
            gettype('task'),
            'tasks',
        )]

    @property
    def coalitions(self):
        target = LazyTarget.GetTarget()

        return (value(coal.AddressOf()) for coal in ccol.SMRHash(
            target.chkFindFirstGlobalVariable('coalition_hash'),
            target.chkFindFirstGlobalVariable('coal_hash_traits'),
        ))

    @property
    def thread_groups(self):
        target = LazyTarget.GetTarget()

        return (value(tg.AddressOf()) for tg in ccol.iter_queue_entries(
            target.chkFindFirstGlobalVariable('tg_queue'),
            gettype('thread_group'),
            'tg_queue_chain',
        ))

    @property
    def terminated_tasks(self):
        target = LazyTarget.GetTarget()

        return (value(t.AddressOf()) for t in ccol.iter_queue(
            target.chkFindFirstGlobalVariable('terminated_tasks'),
            gettype('task'),
            'tasks',
        ))

    @property
    def terminated_threads(self):
        target = LazyTarget.GetTarget()

        return (value(t.AddressOf()) for t in ccol.iter_queue(
            target.chkFindFirstGlobalVariable('terminated_threads'),
            gettype('thread'),
            'threads',
        ))

    @property
    def procs(self):
        target = LazyTarget.GetTarget()

        return (value(p.AddressOf()) for p in ccol.iter_LIST_HEAD(
            target.chkFindFirstGlobalVariable('allproc'),
            'p_list',
        ))

    @property
    def interrupt_stats(self):
        target = LazyTarget.GetTarget()

        return (value(stat.AddressOf()) for stat in ccol.iter_queue(
            target.chkFindFirstGlobalVariable('gInterruptAccountingDataList'),
            gettype('IOInterruptAccountingData'),
            'chain',
        ))

    @property
    def zombprocs(self):
        target = LazyTarget.GetTarget()

        return (value(p.AddressOf()) for p in ccol.iter_LIST_HEAD(
            target.chkFindFirstGlobalVariable('zombproc'),
            'p_list',
        ))

    @property
    def version(self):
        return str(self.globals.version)

    @property
    def arch(self):
        return LazyTarget.GetTarget().triple.split('-', 1)[0]

    @property
    def ptrsize(self):
        return LazyTarget.GetTarget().GetAddressByteSize()

    @property
    def VM_MIN_KERNEL_ADDRESS(self):
        if self.arch == 'x86_64':
            return 0xffffff8000000000
        else:
            return 0xffffffe00000000

    @property
    def VM_MIN_KERNEL_AND_KEXT_ADDRESS(self):
        if self.arch == 'x86_64':
            return 0xffffff8000000000 - 0x80000000
        else:
            return 0xffffffe00000000
