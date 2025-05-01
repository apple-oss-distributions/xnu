#!/usr/bin/env python3
import sys
import struct
import mmap
import json
import copy
import re
import base64
import argparse
import logging
import contextlib
import base64
import zlib

long = int

class Globals(object):
    pass
G = Globals()
G.accept_incomplete_data = False
G.data_was_incomplete = False

kcdata_type_def = {
    'KCDATA_TYPE_INVALID':              0x0,
    'KCDATA_TYPE_STRING_DESC':          0x1,
    'KCDATA_TYPE_UINT32_DESC':          0x2,
    'KCDATA_TYPE_UINT64_DESC':          0x3,
    'KCDATA_TYPE_INT32_DESC':           0x4,
    'KCDATA_TYPE_INT64_DESC':           0x5,
    'KCDATA_TYPE_BINDATA_DESC':         0x6,
    'KCDATA_TYPE_ARRAY':                0x11,
    'KCDATA_TYPE_TYPEDEFINITION':       0x12,
    'KCDATA_TYPE_CONTAINER_BEGIN':      0x13,
    'KCDATA_TYPE_CONTAINER_END':        0x14,

    'KCDATA_TYPE_ARRAY_PAD0':           0x20,
    'KCDATA_TYPE_ARRAY_PAD1':           0x21,
    'KCDATA_TYPE_ARRAY_PAD2':           0x22,
    'KCDATA_TYPE_ARRAY_PAD3':           0x23,
    'KCDATA_TYPE_ARRAY_PAD4':           0x24,
    'KCDATA_TYPE_ARRAY_PAD5':           0x25,
    'KCDATA_TYPE_ARRAY_PAD6':           0x26,
    'KCDATA_TYPE_ARRAY_PAD7':           0x27,
    'KCDATA_TYPE_ARRAY_PAD8':           0x28,
    'KCDATA_TYPE_ARRAY_PAD9':           0x29,
    'KCDATA_TYPE_ARRAY_PADa':           0x2a,
    'KCDATA_TYPE_ARRAY_PADb':           0x2b,
    'KCDATA_TYPE_ARRAY_PADc':           0x2c,
    'KCDATA_TYPE_ARRAY_PADd':           0x2d,
    'KCDATA_TYPE_ARRAY_PADe':           0x2e,
    'KCDATA_TYPE_ARRAY_PADf':           0x2f,

    'KCDATA_TYPE_LIBRARY_LOADINFO':     0x30,
    'KCDATA_TYPE_LIBRARY_LOADINFO64':   0x31,
    'KCDATA_TYPE_TIMEBASE':             0x32,
    'KCDATA_TYPE_MACH_ABSOLUTE_TIME':   0x33,
    'KCDATA_TYPE_TIMEVAL':              0x34,
    'KCDATA_TYPE_USECS_SINCE_EPOCH':    0x35,
    'KCDATA_TYPE_PID':                  0x36,
    'KCDATA_TYPE_PROCNAME':             0x37,
    'KCDATA_TYPE_NESTED_KCDATA':        0x38,
    'KCDATA_TYPE_LIBRARY_AOTINFO':      0x39,

    'STACKSHOT_KCCONTAINER_TASK':       0x903,
    'STACKSHOT_KCCONTAINER_THREAD':     0x904,
    'STACKSHOT_KCTYPE_DONATING_PIDS':   0x907,
    'STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO': 0x908,
    'STACKSHOT_KCTYPE_THREAD_NAME':     0x909,
    'STACKSHOT_KCTYPE_KERN_STACKFRAME': 0x90A,
    'STACKSHOT_KCTYPE_KERN_STACKFRAME64': 0x90B,
    'STACKSHOT_KCTYPE_USER_STACKFRAME': 0x90C,
    'STACKSHOT_KCTYPE_USER_STACKFRAME64': 0x90D,
    'STACKSHOT_KCTYPE_BOOTARGS':        0x90E,
    'STACKSHOT_KCTYPE_OSVERSION':       0x90F,
    'STACKSHOT_KCTYPE_KERN_PAGE_SIZE':  0x910,
    'STACKSHOT_KCTYPE_JETSAM_LEVEL':    0x911,
    'STACKSHOT_KCTYPE_DELTA_SINCE_TIMESTAMP': 0x912,
    'STACKSHOT_KCTYPE_KERN_STACKLR':  0x913,
    'STACKSHOT_KCTYPE_KERN_STACKLR64':  0x914,
    'STACKSHOT_KCTYPE_USER_STACKLR':  0x915,
    'STACKSHOT_KCTYPE_USER_STACKLR64':  0x916,
    'STACKSHOT_KCTYPE_NONRUNNABLE_TIDS':  0x917,
    'STACKSHOT_KCTYPE_NONRUNNABLE_TASKS':  0x918,
    'STACKSHOT_KCTYPE_CPU_TIMES': 0x919,
    'STACKSHOT_KCTYPE_STACKSHOT_DURATION': 0x91a,
    'STACKSHOT_KCTYPE_STACKSHOT_FAULT_STATS': 0x91b,
    'STACKSHOT_KCTYPE_KERNELCACHE_LOADINFO': 0x91c,
    'STACKSHOT_KCTYPE_THREAD_WAITINFO' : 0x91d,
    'STACKSHOT_KCTYPE_THREAD_GROUP_SNAPSHOT' : 0x91e,
    'STACKSHOT_KCTYPE_THREAD_GROUP' : 0x91f,
    'STACKSHOT_KCTYPE_JETSAM_COALITION_SNAPSHOT' : 0x920,
    'STACKSHOT_KCTYPE_JETSAM_COALITION' : 0x921,
    'STACKSHOT_KCTYPE_THREAD_POLICY_VERSION': 0x922,
    'STACKSHOT_KCTYPE_INSTRS_CYCLES' : 0x923,
    'STACKSHOT_KCTYPE_USER_STACKTOP' : 0x924,
    'STACKSHOT_KCTYPE_ASID' : 0x925,
    'STACKSHOT_KCTYPE_PAGE_TABLES' : 0x926,
    'STACKSHOT_KCTYPE_SYS_SHAREDCACHE_LAYOUT' : 0x927,
    'STACKSHOT_KCTYPE_THREAD_DISPATCH_QUEUE_LABEL' : 0x928,
    'STACKSHOT_KCTYPE_THREAD_TURNSTILEINFO' : 0x929,
    'STACKSHOT_KCTYPE_TASK_CPU_ARCHITECTURE' : 0x92a,
    'STACKSHOT_KCTYPE_LATENCY_INFO' : 0x92b,
    'STACKSHOT_KCTYPE_LATENCY_INFO_TASK' : 0x92c,
    'STACKSHOT_KCTYPE_LATENCY_INFO_THREAD' : 0x92d,
    'STACKSHOT_KCTYPE_LOADINFO64_TEXT_EXEC' : 0x92e,
    'STACKSHOT_KCTYPE_AOTCACHE_LOADINFO' : 0x92f,
    'STACKSHOT_KCTYPE_TRANSITIONING_TASK_SNAPSHOT' : 0x930,
    'STACKSHOT_KCCONTAINER_TRANSITIONING_TASK' : 0x931,
    'STACKSHOT_KCTYPE_USER_ASYNC_START_INDEX' : 0x932,
    'STACKSHOT_KCTYPE_USER_ASYNC_STACKLR64' : 0x933,
    'STACKSHOT_KCCONTAINER_PORTLABEL' : 0x934,
    'STACKSHOT_KCTYPE_PORTLABEL' : 0x935,
    'STACKSHOT_KCTYPE_PORTLABEL_NAME' : 0x936,
    'STACKSHOT_KCTYPE_DYLD_COMPACTINFO' : 0x937,
    'STACKSHOT_KCTYPE_SUSPENSION_INFO' : 0x938,
    'STACKSHOT_KCTYPE_SUSPENSION_SOURCE' : 0x939,
    'STACKSHOT_KCTYPE_TASK_DELTA_SNAPSHOT': 0x940,
    'STACKSHOT_KCTYPE_THREAD_DELTA_SNAPSHOT': 0x941,
    'STACKSHOT_KCCONTAINER_SHAREDCACHE' : 0x942,
    'STACKSHOT_KCTYPE_SHAREDCACHE_INFO' : 0x943,
    'STACKSHOT_KCTYPE_SHAREDCACHE_AOTINFO' : 0x944,
    'STACKSHOT_KCTYPE_SHAREDCACHE_ID' : 0x945,
    'STACKSHOT_KCTYPE_CODESIGNING_INFO' : 0x946,
    'STACKSHOT_KCTYPE_OS_BUILD_VERSION' : 0x947,
    'STACKSHOT_KCTYPE_KERN_EXCLAVES_THREADINFO' : 0x948,
    'STACKSHOT_KCCONTAINER_EXCLAVES' : 0x949,
    'STACKSHOT_KCCONTAINER_EXCLAVE_SCRESULT' : 0x94a,
    'STACKSHOT_KCTYPE_EXCLAVE_SCRESULT_INFO' : 0x94b,
    'STACKSHOT_KCCONTAINER_EXCLAVE_IPCSTACKENTRY' : 0x94c,
    'STACKSHOT_KCTYPE_EXCLAVE_IPCSTACKENTRY_INFO' : 0x94d,
    'STACKSHOT_KCTYPE_EXCLAVE_IPCSTACKENTRY_ECSTACK' : 0x94e,
    'STACKSHOT_KCCONTAINER_EXCLAVE_ADDRESSSPACE' : 0x94f,
    'STACKSHOT_KCTYPE_EXCLAVE_ADDRESSSPACE_INFO' : 0x950,
    'STACKSHOT_KCTYPE_EXCLAVE_ADDRESSSPACE_NAME' : 0x951,
    'STACKSHOT_KCCONTAINER_EXCLAVE_TEXTLAYOUT' : 0x952,
    'STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_INFO' : 0x953,
    'STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_SEGMENTS' : 0x954,
    'STACKSHOT_KCTYPE_KERN_EXCLAVES_CRASH_THREADINFO' : 0x955,
    'STACKSHOT_KCTYPE_LATENCY_INFO_CPU': 0x956,

    'KCDATA_TYPE_BUFFER_END':      0xF19158ED,

    'TASK_CRASHINFO_EXTMODINFO':           0x801,
    'TASK_CRASHINFO_BSDINFOWITHUNIQID':    0x802,
    'TASK_CRASHINFO_TASKDYLD_INFO':        0x803,
    'TASK_CRASHINFO_UUID':                 0x804,
    'TASK_CRASHINFO_PID':                  0x805,
    'TASK_CRASHINFO_PPID':                 0x806,

    # Don't want anyone using this.  It's struct rusage from whatever machine generated the data
    #'TASK_CRASHINFO_RUSAGE':               0x807,
    'Type_0x807':               0x807,

    'TASK_CRASHINFO_RUSAGE_INFO':          0x808,
    'TASK_CRASHINFO_PROC_NAME':            0x809,
    'TASK_CRASHINFO_PROC_STARTTIME':       0x80B,
    'TASK_CRASHINFO_USERSTACK':            0x80C,
    'TASK_CRASHINFO_ARGSLEN':              0x80D,
    'TASK_CRASHINFO_EXCEPTION_CODES':      0x80E,
    'TASK_CRASHINFO_PROC_PATH':            0x80F,
    'TASK_CRASHINFO_PROC_CSFLAGS':         0x810,
    'TASK_CRASHINFO_PROC_STATUS':          0x811,
    'TASK_CRASHINFO_UID':                  0x812,
    'TASK_CRASHINFO_GID':                  0x813,
    'TASK_CRASHINFO_PROC_ARGC':            0x814,
    'TASK_CRASHINFO_PROC_FLAGS':           0x815,
    'TASK_CRASHINFO_CPUTYPE':              0x816,
    'TASK_CRASHINFO_WORKQUEUEINFO':        0x817,
    'TASK_CRASHINFO_RESPONSIBLE_PID':      0x818,
    'TASK_CRASHINFO_DIRTY_FLAGS':          0x819,
    'TASK_CRASHINFO_CRASHED_THREADID':     0x81A,
    'TASK_CRASHINFO_COALITION_ID':         0x81B,
    'TASK_CRASHINFO_JIT_ADDRESS_RANGE':    0x840,
    'TASK_CRASHINFO_MB':                   0x841,
    'TASK_CRASHINFO_CS_AUXILIARY_INFO':    0x842,
    'EXIT_REASON_SNAPSHOT':                0x1001,
    'EXIT_REASON_USER_DESC':               0x1002,
    'EXIT_REASON_USER_PAYLOAD':            0x1003,
    'EXIT_REASON_CODESIGNING_INFO':        0x1004,
    'EXIT_REASON_WORKLOOP_ID':             0x1005,
    'EXIT_REASON_DISPATCH_QUEUE_NO':       0x1006,
    'KCDATA_BUFFER_BEGIN_CRASHINFO':       0xDEADF157,
    'KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT': 0xDE17A59A,
    'KCDATA_BUFFER_BEGIN_STACKSHOT':       0x59a25807,
    'KCDATA_BUFFER_BEGIN_COMPRESSED':      0x434f4d50,
    'KCDATA_BUFFER_BEGIN_OS_REASON':       0x53A20900,
    'KCDATA_BUFFER_BEGIN_XNUPOST_CONFIG':  0x1E21C09F
}
kcdata_type_def_rev = dict((v, k) for k, v in iter(kcdata_type_def.items()))

KNOWN_TYPES_COLLECTION = {}

KNOWN_TOPLEVEL_CONTAINER_TYPES = ()

def enum(**args):
    return type('enum', (), args)

#
# Decode bytes as UTF-8, using surrogateescape if there are invalid UTF-8
# sequences; see PEP-383
#
def BytesToString(b):
    if isinstance(b, str):
        return b
    return b.decode('utf-8', errors="surrogateescape")

# important keys
SC_SLID_FIRSTMAPPING_KEY = 'sharedCacheSlidFirstMapping'

# important builtin types
KCSUBTYPE_TYPE = enum(KC_ST_CHAR=1, KC_ST_INT8=2, KC_ST_UINT8=3, KC_ST_INT16=4, KC_ST_UINT16=5, KC_ST_INT32=6, KC_ST_UINT32=7, KC_ST_INT64=8, KC_ST_UINT64=9)


LEGAL_OLD_STYLE_ARRAY_TYPE_NAMES = ['KCDATA_TYPE_LIBRARY_LOADINFO',
                                    'KCDATA_TYPE_LIBRARY_LOADINFO64',
                                    'STACKSHOT_KCTYPE_KERN_STACKFRAME',
                                    'STACKSHOT_KCTYPE_USER_STACKFRAME',
                                    'STACKSHOT_KCTYPE_KERN_STACKFRAME64',
                                    'STACKSHOT_KCTYPE_USER_STACKFRAME64',
                                    'STACKSHOT_KCTYPE_DONATING_PIDS',
                                    'STACKSHOT_KCTYPE_THREAD_DELTA_SNAPSHOT']

KCDATA_FLAGS_STRUCT_PADDING_MASK = 0xf
KCDATA_FLAGS_STRUCT_HAS_PADDING = 0x80

class KCSubTypeElement(object):
    """convert kcdata_subtype_descriptor to """
    _unpack_formats = (None, 'c', 'b', 'B', 'h', 'H', 'i', 'I', 'q', 'Q')
    _ctypes = ('Unknown', 'char', 'int8_t', 'uint8_t', 'int16_t', 'uint16_t', 'int32_t', 'uint32_t', 'int64_t', 'uint64_t')

    def __init__(self, st_name, st_type, st_size, st_offset=0, st_flag=0, custom_repr=None):
        self.name = st_name
        self.offset = st_offset
        self.type_id = st_type
        if st_type <= 0 or st_type > KCSUBTYPE_TYPE.KC_ST_UINT64:
            raise ValueError("Invalid type passed %d" % st_type)
        self.unpack_fmt = KCSubTypeElement._unpack_formats[self.type_id]
        self.size = st_size
        self.totalsize = st_size
        self.count = 1
        self.is_array_type = False
        self.custom_JsonRepr = custom_repr
        if (st_flag & 0x1) == 0x1:
            self.is_array_type = True
            self.size = st_size & 0xffff
            self.count = (st_size >> 16) & 0xffff
            self.totalsize = self.size * self.count

    @staticmethod
    def GetSizeForArray(el_count, el_size):
        return ((el_count & 0xffff) << 16) | (el_size & 0xffff)

    @staticmethod
    def FromBinaryTypeData(byte_data):
        (st_flag, st_type, st_offset, st_size, st_name) = struct.unpack_from('=BBHI32s', byte_data)
        st_name = BytesToString(st_name).rstrip('\0')
        return KCSubTypeElement(st_name, st_type, st_size, st_offset, st_flag)

    @staticmethod
    def FromBasicCtype(st_name, st_type, st_offset=0, legacy_size=None):
        if st_type <= 0 or st_type > KCSUBTYPE_TYPE.KC_ST_UINT64:
            raise ValueError("Invalid type passed %d" % st_type)
        st_size = struct.calcsize(KCSubTypeElement._unpack_formats[st_type])
        st_flag = 0
        retval = KCSubTypeElement(st_name, st_type, st_size, st_offset, st_flag, KCSubTypeElement._get_naked_element_value)
        if legacy_size:
            retval.legacy_size = legacy_size
        return retval

    @staticmethod
    def FromKCSubTypeElement(other, name_override=''):
        _copy = copy.copy(other)
        if name_override:
            _copy.name = name_override
        return copy

    def GetName(self):
        return self.name

    def GetTotalSize(self):
        return self.totalsize

    def GetValueAsString(self, base_data, array_pos=0):
        v = self.GetValue(base_data, array_pos)
        if isinstance(v, bytes):
            return BytesToString(v)
        return str(v)

    def GetValue(self, base_data, array_pos=0):
        return struct.unpack_from(self.unpack_fmt, base_data[self.offset + (array_pos * self.size):])[0]

    @staticmethod
    def _get_naked_element_value(elementValue, elementName):
        return json.dumps(elementValue)

    def __str__(self):
        if self.is_array_type:
            return '[%d,%d] %s  %s[%d];' % (self.offset, self.totalsize, self.GetCTypeDesc(), self.name, self.count)
        return '[%d,%d] %s  %s;' % (self.offset, self.totalsize, self.GetCTypeDesc(), self.name)

    def __repr__(self):
        return str(self)

    def GetCTypeDesc(self):
        return KCSubTypeElement._ctypes[self.type_id]

    def GetStringRepr(self, base_data):
        if not self.is_array_type:
            return self.GetValueAsString(base_data)
        if self.type_id == KCSUBTYPE_TYPE.KC_ST_CHAR:
            str_len = self.count
            if len(base_data) < str_len:
                str_len = len(base_data)
            str_arr = []
            for i in range(str_len):
                _v = self.GetValue(base_data, i)
                if ord(_v) == 0:
                    break
                str_arr.append(self.GetValueAsString(base_data, i))
            return json.dumps(''.join(str_arr))

        count = self.count
        if count > len(base_data)//self.size:
            count = len(base_data)//self.size

        o = '[' + ','.join([self.GetValueAsString(base_data, i) for i in range(count)]) + ']'

        return o

    def GetJsonRepr(self, base_data, flags=0):
        if (flags & (KCDATA_FLAGS_STRUCT_HAS_PADDING | KCDATA_FLAGS_STRUCT_PADDING_MASK)) != 0:
            padding = (flags & KCDATA_FLAGS_STRUCT_PADDING_MASK)
            if padding:
                base_data = base_data[:-padding]
        if self.custom_JsonRepr:
            if self.is_array_type:
                e_data = [self.GetValue(base_data, i) for i in range(self.count)]
            else:
                e_data = self.GetValue(base_data)
            return self.custom_JsonRepr(e_data, self.name)
        return self.GetStringRepr(base_data)

    def sizeof(self):
        return self.totalsize

    def ShouldSkip(self, data):
        return len(data) < self.offset + self.totalsize

    def ShouldMerge(self):
        return False


class KCTypeDescription(object):
    def __init__(self, t_type_id, t_elements=[], t_name='anon', custom_repr=None, legacy_size=None, merge=False, naked=False):
        self.type_id = t_type_id
        self.elements = t_elements
        self.name = t_name
        self.totalsize = 0
        self.custom_JsonRepr = custom_repr
        if legacy_size:
            self.legacy_size = legacy_size
        self.merge = merge
        self.naked = naked
        for e in self.elements:
            self.totalsize += e.GetTotalSize()

    def ValidateData(self, base_data):
        if len(base_data) >= self.totalsize:
            return True
        return False

    def GetTypeID(self):
        return self.type_id

    def GetName(self):
        return self.name

    def __str__(self):
        o = '%s {\n\t' % self.name + "\n\t".join([str(e) for e in self.elements]) + '\n};'
        return o

    @staticmethod
    def FromKCTypeDescription(other, t_type_id, t_name):
        retval = KCTypeDescription(t_type_id, other.elements, t_name, other.custom_JsonRepr,
                                   legacy_size=getattr(other, 'legacy_size', None))
        return retval

    def ShouldMerge(self):
        return self.merge

    def GetJsonRepr(self, base_data, flags):
        if (flags & (KCDATA_FLAGS_STRUCT_HAS_PADDING | KCDATA_FLAGS_STRUCT_PADDING_MASK)) != 0:
            padding = (flags & KCDATA_FLAGS_STRUCT_PADDING_MASK)
            if padding:
                base_data = base_data[:-padding]
        elif hasattr(self, 'legacy_size') and len(base_data) == self.legacy_size + ((-self.legacy_size) & 0xf):
            base_data = base_data[:self.legacy_size]
        if self.custom_JsonRepr:
            return self.custom_JsonRepr([e.GetValue(base_data) for e in self.elements])
        if self.naked:
            o = ", ".join([e.GetJsonRepr(base_data) for e in self.elements if not e.ShouldSkip(base_data)])
        else:
            o = ", ".join(['"%s": %s' % (e.GetName(), e.GetJsonRepr(base_data)) for e in self.elements if not e.ShouldSkip(base_data)])
        if not self.merge:
            o = '{' + o + '}'
        return o

    def sizeof(self):
        return max(st.totalsize + st.offset for st in self.elements)


def GetTypeNameForKey(k):
    retval = "0x%x" % k
    if k in KNOWN_TYPES_COLLECTION:
        retval = KNOWN_TYPES_COLLECTION[k].GetName()
    elif k in kcdata_type_def_rev:
        retval = kcdata_type_def_rev[k]
    return retval


def GetTypeForName(n):
    ret = 0
    if n in kcdata_type_def:
        ret = kcdata_type_def[n]
    return ret


LEGAL_OLD_STYLE_ARRAY_TYPES = list(map(GetTypeForName, LEGAL_OLD_STYLE_ARRAY_TYPE_NAMES))

kcdata_type_def_rev[GetTypeForName('KCDATA_BUFFER_BEGIN_STACKSHOT')] = 'kcdata_stackshot'
kcdata_type_def_rev[GetTypeForName('KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT')] = 'kcdata_delta_stackshot'
kcdata_type_def_rev[GetTypeForName('KCDATA_BUFFER_BEGIN_CRASHINFO')] = 'kcdata_crashinfo'
kcdata_type_def_rev[GetTypeForName('KCDATA_BUFFER_BEGIN_OS_REASON')] = 'kcdata_reason'
kcdata_type_def_rev[GetTypeForName('STACKSHOT_KCCONTAINER_TASK')] = 'task_snapshots'
kcdata_type_def_rev[GetTypeForName('STACKSHOT_KCCONTAINER_TRANSITIONING_TASK')] = 'transitioning_task_snapshots'
kcdata_type_def_rev[GetTypeForName('STACKSHOT_KCCONTAINER_THREAD')] = 'thread_snapshots'
kcdata_type_def_rev[GetTypeForName('STACKSHOT_KCCONTAINER_PORTLABEL')] = 'portlabels'
kcdata_type_def_rev[GetTypeForName('STACKSHOT_KCCONTAINER_SHAREDCACHE')] = 'shared_caches'
kcdata_type_def_rev[GetTypeForName('KCDATA_BUFFER_BEGIN_XNUPOST_CONFIG')] = 'xnupost_testconfig'
kcdata_type_def_rev[GetTypeForName('STACKSHOT_KCCONTAINER_EXCLAVES')] = 'threads_exclave'
kcdata_type_def_rev[GetTypeForName('STACKSHOT_KCCONTAINER_EXCLAVE_SCRESULT')] = 'thread_exclave'
kcdata_type_def_rev[GetTypeForName('STACKSHOT_KCCONTAINER_EXCLAVE_IPCSTACKENTRY')] = 'exclave_ipcstackentry'
kcdata_type_def_rev[GetTypeForName('STACKSHOT_KCCONTAINER_EXCLAVE_ADDRESSSPACE')] = 'exclave_addressspace'
kcdata_type_def_rev[GetTypeForName('STACKSHOT_KCCONTAINER_EXCLAVE_TEXTLAYOUT')] = 'exclave_textlayout'

class Indent(object):
    def __init__(self):
        self.n = 0
    def __call__(self, end=False):
        if end:
            return " " * (self.n-4)
        else:
            return " " * self.n
    @contextlib.contextmanager
    def indent(self):
        self.n += 4
        try:
            yield
        finally:
            self.n -= 4

INDENT = Indent()

class KCObject(object):

    def __init__(self, type_code, data, offset, flags=0):

        self.i_type = type_code
        self.i_data = data
        self.offset = offset
        self.i_size = len(data)
        self.i_flags = flags
        self.obj_collection = []
        self.obj = {}
        self.is_container_type = False
        self.is_array_type = False
        self.is_naked_type = False
        self.nested_kcdata = None
        self.i_name = GetTypeNameForKey(type_code)

        self.ParseData()

        if self.i_type == GetTypeForName('KCDATA_TYPE_CONTAINER_BEGIN'):
            self.__class__ = KCContainerObject
        elif self.i_type == GetTypeForName('KCDATA_BUFFER_BEGIN_COMPRESSED'):
            self.__class__ = KCCompressedBufferObject
        elif self.i_type in KNOWN_TOPLEVEL_CONTAINER_TYPES:
            self.__class__ = KCBufferObject

        self.InitAfterParse()

    def __str__(self):
        return "<KCObject at 0x%x>" % self.offset

    def InitAfterParse(self):
        pass

    @staticmethod
    def FromKCItem(kcitem):
        return KCObject(kcitem.i_type, kcitem.i_data, kcitem.i_offset, kcitem.i_flags)

    def IsContainerEnd(self):
        return self.i_type == GetTypeForName('KCDATA_TYPE_CONTAINER_END')

    def IsBufferEnd(self):
        return self.i_type == GetTypeForName('KCDATA_TYPE_BUFFER_END')

    def IsArray(self):
        return self.is_array_type

    def ShouldMerge(self):
        if self.nested_kcdata:
            return True
        elif not self.is_array_type and self.i_type in KNOWN_TYPES_COLLECTION:
            return KNOWN_TYPES_COLLECTION[self.i_type].ShouldMerge()
        else:
            return False

    def GetJsonRepr(self):
        if self.is_array_type:
            return '[' + ', '.join([i.GetJsonRepr() for i in self.obj_collection]) + ']'
        if self.i_type in KNOWN_TYPES_COLLECTION:
            return KNOWN_TYPES_COLLECTION[self.i_type].GetJsonRepr(self.i_data, self.i_flags)
        if self.is_naked_type:
            return json.dumps(self.obj)
        if self.nested_kcdata:
            return self.nested_kcdata.GetJsonRepr()

        raise NotImplementedError("Broken GetJsonRepr implementation")

    def ParseData(self):

        logging.info(self.i_type)
        if self.i_type == GetTypeForName('KCDATA_TYPE_CONTAINER_BEGIN'):
            self.obj['uniqID'] = self.i_flags
            self.i_name = str(self.obj['uniqID'])
            self.obj['typeID'] = struct.unpack_from('I', self.i_data)[0]
            logging.info("0x%08x: %sCONTAINER: %s(%x)" % (self.offset, INDENT(), GetTypeNameForKey(self.obj['typeID']), self.i_flags))

        elif self.i_type in (KNOWN_TOPLEVEL_CONTAINER_TYPES):
            self.obj['uniqID'] = self.i_name
            self.obj['typeID'] = self.i_type
            logging.info("0x%08x: %s%s" % (self.offset, INDENT(), self.i_name))

        elif self.i_type == GetTypeForName('KCDATA_TYPE_CONTAINER_END'):
            self.obj['uniqID'] = self.i_flags
            logging.info("0x%08x: %sEND" % (self.offset, INDENT(end=True)))

        elif self.i_type == GetTypeForName('KCDATA_TYPE_BUFFER_END'):
            self.obj = ''
            logging.info("0x%08x: %sEND_BUFFER" % (self.offset, INDENT(end=True)))

        elif self.i_type == GetTypeForName('KCDATA_TYPE_UINT32_DESC'):
            self.is_naked_type = True
            u_d = struct.unpack_from('32sI', self.i_data)
            self.i_name = BytesToString(u_d[0]).rstrip('\0')
            self.obj = u_d[1]
            logging.info("0x%08x: %s%s" % (self.offset, INDENT(), self.i_name))

        elif self.i_type == GetTypeForName('KCDATA_TYPE_UINT64_DESC'):
            self.is_naked_type = True
            u_d = struct.unpack_from('32sQ', self.i_data)
            self.i_name = BytesToString(u_d[0]).rstrip('\0')
            self.obj = u_d[1]
            logging.info("0x%08x: %s%s" % (self.offset, INDENT(), self.i_name))

        elif self.i_type == GetTypeForName('KCDATA_TYPE_TYPEDEFINITION'):
            self.is_naked_type = True
            u_d = struct.unpack_from('II32s', self.i_data)
            self.obj['name'] = BytesToString(u_d[2]).split(chr(0))[0]
            self.i_name = "typedef[%s]" % self.obj['name']
            self.obj['typeID'] = u_d[0]
            self.obj['numOfFields'] = u_d[1]
            element_arr = []
            for i in range(u_d[1]):
                e = KCSubTypeElement.FromBinaryTypeData(self.i_data[40+(i*40):])
                element_arr.append(e)
            type_desc = KCTypeDescription(u_d[0], element_arr, self.obj['name'])
            self.obj['fields'] = [str(e) for e in element_arr]
            KNOWN_TYPES_COLLECTION[type_desc.GetTypeID()] = type_desc
            logging.info("0x%08x: %s%s" % (self.offset, INDENT(), self.i_name))

        elif self.i_type == GetTypeForName('KCDATA_TYPE_ARRAY'):
            self.is_array_type = True
            e_t = (self.i_flags >> 32) & 0xffffffff
            if e_t not in LEGAL_OLD_STYLE_ARRAY_TYPES:
                raise Exception("illegal old-style array type: %s (0x%x)" % (GetTypeNameForKey(e_t), e_t))
            e_c = self.i_flags & 0xffffffff
            e_s = KNOWN_TYPES_COLLECTION[e_t].legacy_size
            if e_s * e_c > self.i_size:
                raise Exception("array too small for its count")
            self.obj['typeID'] = e_t
            self.i_name = GetTypeNameForKey(e_t)
            self.i_type = e_t
            self.obj['numOfElements'] = e_c
            self.obj['sizeOfElement'] = e_s
            logging.info("0x%08x: %sARRAY: %s" % (self.offset, INDENT(), self.i_name))
            #populate the array here by recursive creation of KCObject
            with INDENT.indent():
                for _i in range(e_c):
                    _o = KCObject(e_t, self.i_data[(_i * e_s):(_i * e_s) + e_s], self.offset + _i*e_s)
                    self.obj_collection.append(_o)

        elif self.i_type >= GetTypeForName('KCDATA_TYPE_ARRAY_PAD0') and self.i_type <= GetTypeForName('KCDATA_TYPE_ARRAY_PADf'):
            self.is_array_type = True
            e_t = (self.i_flags >> 32) & 0xffffffff
            e_c = self.i_flags & 0xffffffff
            e_s = (self.i_size - (self.i_type & 0xf)) // e_c if e_c != 0 else None
            self.obj['typeID'] = e_t
            self.i_name = GetTypeNameForKey(e_t)
            self.i_type = e_t
            self.obj['numOfElements'] = e_c
            self.obj['sizeOfElement'] = e_s
            logging.info("0x%08x: %sARRAY: %s" % (self.offset, INDENT(), self.i_name))
            #populate the array here by recursive creation of KCObject
            with INDENT.indent():
                for _i in range(e_c):
                    _o = KCObject(e_t, self.i_data[(_i * e_s):(_i * e_s) + e_s], self.offset + _i*e_s)
                    self.obj_collection.append(_o)

        elif self.i_type == GetTypeForName('KCDATA_TYPE_NESTED_KCDATA'):
            logging.info("0x%08x: %sNESTED_KCDATA" % (self.offset, INDENT()))
            with INDENT.indent():
                nested_iterator = kcdata_item_iterator(self.i_data[:self.i_size])
                nested_buffer = KCObject.FromKCItem(next(nested_iterator))
                if not isinstance(nested_buffer, KCBufferObject):
                    raise Exception("nested buffer isn't a KCBufferObject")
                nested_buffer.ReadItems(nested_iterator)
            self.nested_kcdata = nested_buffer

        elif self.i_type in KNOWN_TYPES_COLLECTION:
            self.i_name = KNOWN_TYPES_COLLECTION[self.i_type].GetName()
            self.is_naked_type = True
            logging.info("0x%08x: %s%s" % (self.offset, INDENT(), self.i_name))
        else:
            self.is_naked_type = True
            #self.obj = "data of len %d" % len(self.i_data)
            #self.obj = ''.join(["%x" % ki for ki in struct.unpack('%dB' % len(self.i_data), self.i_data)])
            if isinstance(self.i_data, str):
                self.obj = list(map(ord, BytesToString(self.i_data)))
            else:
                self.obj = [i for i in self.i_data]
            logging.info("0x%08x: %s%s" % (self.offset, INDENT(), self.i_name))


class KCContainerObject(KCObject):
    def __init__(self, *args, **kwargs):
        assert False

    def InitAfterParse(self):
        self.obj_container_dict = {}
        self.obj_nested_objs = {}

    def ShouldMerge(self):
        return True

    def GetJsonRepr(self):
        # o = '"%s"' % self.obj['uniqID'] + ' : { "typeID" : %d ,' % self.obj['typeID']
        o = '"%s"' % self.obj['uniqID'] + ' : { '
        for (k, v) in self.obj_container_dict.items():
            if v.ShouldMerge():
                o += v.GetJsonRepr() + ","
            else:
                o += ' "%s" : ' % k + v.GetJsonRepr() + ","

        for (k, v) in self.obj_nested_objs.items():
            o += '"%s" : {' % k + ",".join([vi.GetJsonRepr() for vi in v.values()]) + "} ,"

        o = o.rstrip(',') + "}"

        return o

    def AddObject(self, kco):
        assert not kco.IsContainerEnd()
        if isinstance(kco, KCContainerObject):
            type_name = GetTypeNameForKey(kco.obj['typeID'])
            if type_name not in self.obj_nested_objs:
                self.obj_nested_objs[type_name] = {}
            self.obj_nested_objs[type_name][kco.i_name] = kco
            return
        if kco.i_name in self.obj_container_dict:
            if kco.IsArray() and self.obj_container_dict[kco.i_name].IsArray():
                self.obj_container_dict[kco.i_name].obj_collection.extend( kco.obj_collection )
        else:
            self.obj_container_dict[kco.i_name] = kco

    def IsEndMarker(self, o):
        if not o.IsContainerEnd():
            return False
        if o.i_flags != self.i_flags:
            raise Exception("container end marker doesn't match")
        return True

    no_end_message = "could not find container end marker"

    def ReadItems(self, iterator):
        found_end = False
        with INDENT.indent():
            for i in iterator:
                o = KCObject.FromKCItem(i)
                if self.IsEndMarker(o):
                    found_end = True
                    break
                if o.IsBufferEnd():
                    break
                if isinstance(o, KCContainerObject):
                    o.ReadItems(iterator)
                self.AddObject(o)
        if not found_end:
            if G.accept_incomplete_data:
                if not G.data_was_incomplete:
                    print("kcdata.py WARNING: data is incomplete!", file=sys.stderr)
                    G.data_was_incomplete = True
            else:
                raise Exception(self.no_end_message)



class KCBufferObject(KCContainerObject):

    def IsEndMarker(self,o):
        if o.IsContainerEnd():
            raise Exception("container end marker at the toplevel")
        return o.IsBufferEnd()

    no_end_message = "could not find buffer end marker"

class KCCompressedBufferObject(KCContainerObject):

    def ReadItems(self, iterator):
        self.header = dict()
        with INDENT.indent():
            for i in iterator:
                o = KCObject.FromKCItem(i)
                if self.IsEndMarker(o):
                    self.compressed_type = o.i_type
                    self.blob_start = o.offset + 16
                    break
                o.ParseData()
                self.header[o.i_name] = o.obj

    def IsEndMarker(self, o):
        return o.i_type in KNOWN_TOPLEVEL_CONTAINER_TYPES

    def GetCompressedBlob(self, data):
        if self.header['kcd_c_type'] != 1:
            raise NotImplementedError
        blob = data[self.blob_start:self.blob_start+self.header['kcd_c_totalout']]
        if len(blob) != self.header['kcd_c_totalout']:
            raise ValueError
        return blob

    def Decompress(self, data):
        start_marker = struct.pack('<IIII', self.compressed_type, 0, 0, 0)
        end_marker = struct.pack('<IIII', GetTypeForName('KCDATA_TYPE_BUFFER_END'), 0, 0, 0)
        decompressed = zlib.decompress(self.GetCompressedBlob(data))
        if len(decompressed) != self.header['kcd_c_totalin']:
            raise ValueError("length of decompressed: %d vs expected %d" % (len(decompressed), self.header['kcd_c_totalin']))
        alignbytes = b'\x00' * (-len(decompressed) % 16)
        return start_marker + decompressed + alignbytes + end_marker


class KCData_item:
    """ a basic kcdata_item type object.
    """
    header_size = 16  # (uint32_t + uint32_t + uint64_t)

    def __init__(self, item_type, item_size, item_flags, item_data):
        self.i_type = item_type
        self.i_size = item_size
        self.i_flags = item_flags
        self.i_data = item_data
        self.i_offset = None

    def __init__(self, barray, pos=0):
        """ create an object by parsing data from bytes array
            returns : obj - if data is readable
                      raises ValueError if something is not ok.
        """
        self.i_type = struct.unpack('I', barray[pos:pos+4])[0]     # int.from_bytes(barray[pos:pos+4])
        self.i_size = struct.unpack('I', barray[pos+4:pos+8])[0]   # int.from_bytes(barray[pos+4:pos+8])
        self.i_flags = struct.unpack('Q', barray[pos+8:pos+16])[0]  # int.from_bytes(barray[pos+8:pos+16])
        self.i_data = barray[pos+16: (pos + 16 + self.i_size)]
        self.i_offset = pos

    def __len__(self):
        return self.i_size + KCData_item.header_size

    def GetHeaderDescription(self):
        outs = "type: 0x%x size: 0x%x flags: 0x%x  (%s)" % (self.i_type, self.i_size, self.i_flags, GetTypeNameForKey(self.i_type))
        if not self.i_offset is None:
            outs = "pos: 0x%x" % self.i_offset + outs
        return outs

    def __str__(self):
        return self.GetHeaderDescription()

def kcdata_item_iterator(data):
    file_len = len(data)
    curpos = 0
    while curpos < file_len:
        item = KCData_item(data, curpos)
        yield item
        curpos += len(item)

def _get_data_element(elementValues):
    return json.dumps(elementValues[-1])

KNOWN_TOPLEVEL_CONTAINER_TYPES = list(map(GetTypeForName, ('KCDATA_BUFFER_BEGIN_COMPRESSED', 'KCDATA_BUFFER_BEGIN_CRASHINFO', 'KCDATA_BUFFER_BEGIN_STACKSHOT', 'KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT', 'KCDATA_BUFFER_BEGIN_OS_REASON','KCDATA_BUFFER_BEGIN_XNUPOST_CONFIG')))

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_UINT32_DESC')] = KCTypeDescription(GetTypeForName('KCDATA_TYPE_UINT32_DESC'), (
    KCSubTypeElement('desc', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(32, 1), 0, 1),
    KCSubTypeElement('data', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 32, 0)
),
    'KCDATA_TYPE_UINT32_DESC',
    _get_data_element
)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_UINT64_DESC')] = KCTypeDescription(GetTypeForName('KCDATA_TYPE_UINT64_DESC'), (
    KCSubTypeElement('desc', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(32, 1), 0, 1),
    KCSubTypeElement('data', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 32, 0)
),
    'KCDATA_TYPE_UINT64_DESC',
    _get_data_element
)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_TIMEBASE')] = KCTypeDescription(GetTypeForName('KCDATA_TYPE_TIMEBASE'), (
    KCSubTypeElement('numer', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0),
    KCSubTypeElement('denom', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4, 0)
),
    'mach_timebase_info'
)


STACKSHOT_IO_NUM_PRIORITIES = 4
KNOWN_TYPES_COLLECTION[0x901] = KCTypeDescription(0x901, (
    KCSubTypeElement.FromBasicCtype('ss_disk_reads_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('ss_disk_reads_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('ss_disk_writes_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('ss_disk_writes_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    KCSubTypeElement('ss_io_priority_count', KCSUBTYPE_TYPE.KC_ST_UINT64, KCSubTypeElement.GetSizeForArray(STACKSHOT_IO_NUM_PRIORITIES, 8), 32, 1),
    KCSubTypeElement('ss_io_priority_size', KCSUBTYPE_TYPE.KC_ST_UINT64, KCSubTypeElement.GetSizeForArray(STACKSHOT_IO_NUM_PRIORITIES, 8), 32 + (STACKSHOT_IO_NUM_PRIORITIES * 8), 1),
    KCSubTypeElement.FromBasicCtype('ss_paging_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 32 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_paging_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 40 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_non_paging_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 48 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_non_paging_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 56 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_data_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 64 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_data_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 72 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_metadata_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 80 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_metadata_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 88 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8))
),
    'io_statistics'
)

KNOWN_TYPES_COLLECTION[0x902] = KCTypeDescription(0x902, (
    KCSubTypeElement('snapshot_magic', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 0, 0),
    KCSubTypeElement('free_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 1, 0),
    KCSubTypeElement('active_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 2, 0),
    KCSubTypeElement('inactive_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 3, 0),
    KCSubTypeElement('purgeable_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 4, 0),
    KCSubTypeElement('wired_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 5, 0),
    KCSubTypeElement('speculative_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 6, 0),
    KCSubTypeElement('throttled_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 7, 0),
    KCSubTypeElement('filebacked_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 8, 0),
    KCSubTypeElement('compressions', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 9, 0),
    KCSubTypeElement('decompressions', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 10, 0),
    KCSubTypeElement('compressor_size', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 11, 0),
    KCSubTypeElement('busy_buffer_count', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 4 * 12, 0),
    KCSubTypeElement('pages_wanted', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 13, 0),
    KCSubTypeElement('pages_reclaimed', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 14, 0),
    KCSubTypeElement('pages_wanted_reclaimed_valid', KCSUBTYPE_TYPE.KC_ST_UINT8, 1, 4 * 15, 0)
),
    'mem_and_io_snapshot'
)


KNOWN_TYPES_COLLECTION[0x930] = KCTypeDescription(0x930, (
    KCSubTypeElement.FromBasicCtype('tts_unique_pid', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('tts_ss_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('tts_transition_type', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('tts_pid', KCSUBTYPE_TYPE.KC_ST_INT32, 24),
    KCSubTypeElement('tts_p_comm', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(32, 1), 28, 1)
),
    'transitioning_task_snapshot'
)

KNOWN_TYPES_COLLECTION[0x905] = KCTypeDescription(0x905, (
    KCSubTypeElement.FromBasicCtype('ts_unique_pid', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('ts_ss_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('ts_user_time_in_terminated_thre', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('ts_system_time_in_terminated_th', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    KCSubTypeElement.FromBasicCtype('ts_p_start_sec', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
    KCSubTypeElement.FromBasicCtype('ts_task_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
    KCSubTypeElement.FromBasicCtype('ts_max_resident_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
    KCSubTypeElement.FromBasicCtype('ts_suspend_count', KCSUBTYPE_TYPE.KC_ST_UINT32, 56),
    KCSubTypeElement.FromBasicCtype('ts_faults', KCSUBTYPE_TYPE.KC_ST_UINT32, 60),
    KCSubTypeElement.FromBasicCtype('ts_pageins', KCSUBTYPE_TYPE.KC_ST_UINT32, 64),
    KCSubTypeElement.FromBasicCtype('ts_cow_faults', KCSUBTYPE_TYPE.KC_ST_UINT32, 68),
    KCSubTypeElement.FromBasicCtype('ts_was_throttled', KCSUBTYPE_TYPE.KC_ST_UINT32, 72),
    KCSubTypeElement.FromBasicCtype('ts_did_throttle', KCSUBTYPE_TYPE.KC_ST_UINT32, 76),
    KCSubTypeElement.FromBasicCtype('ts_latency_qos', KCSUBTYPE_TYPE.KC_ST_UINT32, 80),
    KCSubTypeElement.FromBasicCtype('ts_pid', KCSUBTYPE_TYPE.KC_ST_INT32, 84),
    KCSubTypeElement('ts_p_comm', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(32, 1), 88, 1)
),
    'task_snapshot'
)


KNOWN_TYPES_COLLECTION[0x946] = KCTypeDescription(0x946, (
     KCSubTypeElement.FromBasicCtype('csflags', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
     KCSubTypeElement.FromBasicCtype('cs_trust_level', KCSUBTYPE_TYPE.KC_ST_UINT32, 8),
     ),
     'stackshot_task_codesigning_info'
)
KNOWN_TYPES_COLLECTION[0x906] = KCTypeDescription(0x906, (
    KCSubTypeElement.FromBasicCtype('ths_thread_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('ths_wait_event', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('ths_continuation', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('ths_total_syscalls', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    KCSubTypeElement.FromBasicCtype('ths_voucher_identifier', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
    KCSubTypeElement.FromBasicCtype('ths_dqserialnum', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
    KCSubTypeElement.FromBasicCtype('ths_user_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
    KCSubTypeElement.FromBasicCtype('ths_sys_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 56),
    KCSubTypeElement.FromBasicCtype('ths_ss_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 64),
    KCSubTypeElement.FromBasicCtype('ths_last_run_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 72),
    KCSubTypeElement.FromBasicCtype('ths_last_made_runnable_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 80),
    KCSubTypeElement.FromBasicCtype('ths_state', KCSUBTYPE_TYPE.KC_ST_UINT32, 88),
    KCSubTypeElement.FromBasicCtype('ths_sched_flags', KCSUBTYPE_TYPE.KC_ST_UINT32, 92),
    KCSubTypeElement.FromBasicCtype('ths_base_priority', KCSUBTYPE_TYPE.KC_ST_INT16, 96),
    KCSubTypeElement.FromBasicCtype('ths_sched_priority', KCSUBTYPE_TYPE.KC_ST_INT16, 98),
    KCSubTypeElement.FromBasicCtype('ths_eqos', KCSUBTYPE_TYPE.KC_ST_UINT8, 100),
    KCSubTypeElement.FromBasicCtype('ths_rqos', KCSUBTYPE_TYPE.KC_ST_UINT8, 101),
    KCSubTypeElement.FromBasicCtype('ths_rqos_override', KCSUBTYPE_TYPE.KC_ST_UINT8, 102),
    KCSubTypeElement.FromBasicCtype('ths_io_tier', KCSUBTYPE_TYPE.KC_ST_UINT8, 103),
    KCSubTypeElement.FromBasicCtype('ths_thread_t', KCSUBTYPE_TYPE.KC_ST_UINT64, 104),
    KCSubTypeElement.FromBasicCtype('ths_requested_policy', KCSUBTYPE_TYPE.KC_ST_UINT64, 112),
    KCSubTypeElement.FromBasicCtype('ths_effective_policy', KCSUBTYPE_TYPE.KC_ST_UINT64, 120),
),
    'thread_snapshot',
    legacy_size = 0x68
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_DISPATCH_QUEUE_LABEL')] = KCSubTypeElement('dispatch_queue_label', KCSUBTYPE_TYPE.KC_ST_CHAR,
                          KCSubTypeElement.GetSizeForArray(64, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_DELTA_SNAPSHOT')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_THREAD_DELTA_SNAPSHOT'), (
    KCSubTypeElement.FromBasicCtype('tds_thread_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('tds_voucher_identifier', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('tds_ss_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('tds_last_made_runnable_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    KCSubTypeElement.FromBasicCtype('tds_state', KCSUBTYPE_TYPE.KC_ST_UINT32, 32),
    KCSubTypeElement.FromBasicCtype('tds_sched_flags', KCSUBTYPE_TYPE.KC_ST_UINT32, 36),
    KCSubTypeElement.FromBasicCtype('tds_base_priority', KCSUBTYPE_TYPE.KC_ST_INT16, 40),
    KCSubTypeElement.FromBasicCtype('tds_sched_priority', KCSUBTYPE_TYPE.KC_ST_INT16, 42),
    KCSubTypeElement.FromBasicCtype('tds_eqos', KCSUBTYPE_TYPE.KC_ST_UINT8, 44),
    KCSubTypeElement.FromBasicCtype('tds_rqos', KCSUBTYPE_TYPE.KC_ST_UINT8, 45),
    KCSubTypeElement.FromBasicCtype('tds_rqos_override', KCSUBTYPE_TYPE.KC_ST_UINT8, 46),
    KCSubTypeElement.FromBasicCtype('tds_io_tier', KCSUBTYPE_TYPE.KC_ST_UINT8, 47),
    KCSubTypeElement.FromBasicCtype('tds_requested_policy', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
    KCSubTypeElement.FromBasicCtype('tds_effective_policy', KCSUBTYPE_TYPE.KC_ST_UINT64, 56),
),
    'thread_delta_snapshot',
    legacy_size = 48
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_TASK_DELTA_SNAPSHOT')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_TASK_DELTA_SNAPSHOT'), (
    KCSubTypeElement.FromBasicCtype('tds_unique_pid', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('tds_ss_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('tds_user_time_in_terminated_thr', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('tds_system_time_in_terminated_t', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    KCSubTypeElement.FromBasicCtype('tds_task_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
    KCSubTypeElement.FromBasicCtype('tds_max_resident_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
    KCSubTypeElement.FromBasicCtype('tds_suspend_count', KCSUBTYPE_TYPE.KC_ST_UINT32, 48),
    KCSubTypeElement.FromBasicCtype('tds_faults', KCSUBTYPE_TYPE.KC_ST_UINT32, 52),
    KCSubTypeElement.FromBasicCtype('tds_pageins', KCSUBTYPE_TYPE.KC_ST_UINT32, 56),
    KCSubTypeElement.FromBasicCtype('tds_cow_faults', KCSUBTYPE_TYPE.KC_ST_UINT32, 60),
    KCSubTypeElement.FromBasicCtype('tds_was_throttled', KCSUBTYPE_TYPE.KC_ST_UINT32, 64),
    KCSubTypeElement.FromBasicCtype('tds_did_throttle', KCSUBTYPE_TYPE.KC_ST_UINT32, 68),
    KCSubTypeElement.FromBasicCtype('tds_latency_qos', KCSUBTYPE_TYPE.KC_ST_UINT32, 72),
),
    'task_delta_snapshot'
)


KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_NAME')] = KCSubTypeElement('pth_name', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(64, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_SYS_SHAREDCACHE_LAYOUT')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_SYS_SHAREDCACHE_LAYOUT'), (
    KCSubTypeElement('imageLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 8, 1)
),
    'system_shared_cache_layout'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_LIBRARY_LOADINFO64')] = KCTypeDescription(GetTypeForName('KCDATA_TYPE_LIBRARY_LOADINFO64'), (
    KCSubTypeElement('imageLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 8, 1)
),
    'dyld_load_info',
    legacy_size = 24
)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_LIBRARY_LOADINFO')] = KCTypeDescription(GetTypeForName('KCDATA_TYPE_LIBRARY_LOADINFO'), (
    KCSubTypeElement('imageLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 4, 1)
),
    'dyld_load_info',
    legacy_size = 20
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_LOADINFO64_TEXT_EXEC')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_LOADINFO64_TEXT_EXEC'), (
    KCSubTypeElement('imageLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 8, 1),
),
    'dyld_load_info_text_exec'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_AOTCACHE_LOADINFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_AOTCACHE_LOADINFO'), (
    KCSubTypeElement('x86SlidBaseAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
    KCSubTypeElement('x86UUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 8, 1),
    KCSubTypeElement('aotSlidBaseAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 24, 0),
    KCSubTypeElement('aotUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 32, 1),
),
    'dyld_aot_cache_uuid_info'
)
KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_SHAREDCACHE_AOTINFO')] = KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_AOTCACHE_LOADINFO')]

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO'), (
    KCSubTypeElement('imageLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 8, 1),
    KCSubTypeElement('imageSlidBaseAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 24, 0),
    KCSubTypeElement('sharedCacheSlidFirstMapping', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 32, 0),
),
    'shared_cache_dyld_load_info',
    legacy_size = 0x18
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_SHAREDCACHE_INFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_SHAREDCACHE_INFO'), (
    KCSubTypeElement('sharedCacheSlide', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
    KCSubTypeElement('sharedCacheUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 8, 1),
    KCSubTypeElement('sharedCacheUnreliableSlidBaseAd', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 24, 0),
    KCSubTypeElement('sharedCacheSlidFirstMapping', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 32, 0),
    KCSubTypeElement('sharedCacheID', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 40, 0),
    KCSubTypeElement('sharedCacheFlags', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 44, 0),
),
    'shared_cache_dyld_load_info',
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERNELCACHE_LOADINFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_KERNELCACHE_LOADINFO'), (
    KCSubTypeElement('imageLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 8, 1),
),
    'kernelcache_load_info'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_SHAREDCACHE_ID')] = KCSubTypeElement('sharedCacheID', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[0x33] = KCSubTypeElement('mach_absolute_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value)
KNOWN_TYPES_COLLECTION[0x907] = KCSubTypeElement.FromBasicCtype('donating_pids', KCSUBTYPE_TYPE.KC_ST_INT32, legacy_size=4)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_USECS_SINCE_EPOCH')] = KCSubTypeElement('usecs_since_epoch', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME'), (
    KCSubTypeElement.FromBasicCtype('lr', KCSUBTYPE_TYPE.KC_ST_UINT32),
    KCSubTypeElement.FromBasicCtype('sp', KCSUBTYPE_TYPE.KC_ST_UINT32, 4)
),
    'kernel_stack_frames',
    legacy_size = 8
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKLR')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKLR'), (
    KCSubTypeElement.FromBasicCtype('lr', KCSUBTYPE_TYPE.KC_ST_UINT32),
),
    'kernel_stack_frames'
)


KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_USER_STACKFRAME')] = KCTypeDescription.FromKCTypeDescription(
    KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME')],
    GetTypeForName('STACKSHOT_KCTYPE_USER_STACKFRAME'),
    'user_stack_frames'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_USER_STACKLR')] = KCTypeDescription.FromKCTypeDescription(
    KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKLR')],
    GetTypeForName('STACKSHOT_KCTYPE_USER_STACKLR'),
    'user_stack_frames'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME64')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME64'), (
    KCSubTypeElement.FromBasicCtype('lr', KCSUBTYPE_TYPE.KC_ST_UINT64),
    KCSubTypeElement.FromBasicCtype('sp', KCSUBTYPE_TYPE.KC_ST_UINT64, 8)
),
    'kernel_stack_frames',
    legacy_size = 16
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_USER_STACKFRAME64')] = KCTypeDescription.FromKCTypeDescription(
    KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME64')],
    GetTypeForName('STACKSHOT_KCTYPE_USER_STACKFRAME64'),
    'user_stack_frames'
)


KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKLR64')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKLR64'), (
    KCSubTypeElement.FromBasicCtype('lr', KCSUBTYPE_TYPE.KC_ST_UINT64),
),
    'kernel_stack_frames'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_USER_STACKLR64')] = KCTypeDescription.FromKCTypeDescription(
    KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKLR64')],
    GetTypeForName('STACKSHOT_KCTYPE_USER_STACKLR64'),
    'user_stack_frames'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_USER_ASYNC_START_INDEX')] = KCSubTypeElement.FromBasicCtype('user_async_start_index', KCSUBTYPE_TYPE.KC_ST_UINT32)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_USER_ASYNC_STACKLR64')] = KCTypeDescription.FromKCTypeDescription(
    KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKLR64')],
    GetTypeForName('STACKSHOT_KCTYPE_USER_ASYNC_STACKLR64'),
    'user_async_stack_frames'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_NONRUNNABLE_TIDS')] = KCSubTypeElement.FromBasicCtype('nonrunnable_threads', KCSUBTYPE_TYPE.KC_ST_INT64)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_NONRUNNABLE_TASKS')] = KCSubTypeElement.FromBasicCtype('nonrunnable_tasks', KCSUBTYPE_TYPE.KC_ST_INT64)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_OSVERSION')] = KCSubTypeElement('osversion', KCSUBTYPE_TYPE.KC_ST_CHAR,
                          KCSubTypeElement.GetSizeForArray(256, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_BOOTARGS')] = KCSubTypeElement('boot_args', KCSUBTYPE_TYPE.KC_ST_CHAR,
                           KCSubTypeElement.GetSizeForArray(256, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_PAGE_SIZE')] = KCSubTypeElement('kernel_page_size', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_POLICY_VERSION')] = KCSubTypeElement('thread_policy_version', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_JETSAM_LEVEL')] = KCSubTypeElement('jetsam_level', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_DELTA_SINCE_TIMESTAMP')] = KCSubTypeElement("stackshot_delta_since_timestamp", KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_STACKSHOT_FAULT_STATS')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_STACKSHOT_FAULT_STATS'),
            (
                        KCSubTypeElement.FromBasicCtype('sfs_pages_faulted_in', KCSUBTYPE_TYPE.KC_ST_UINT32, 0),
                        KCSubTypeElement.FromBasicCtype('sfs_time_spent_faulting', KCSUBTYPE_TYPE.KC_ST_UINT64, 4),
                        KCSubTypeElement.FromBasicCtype('sfs_system_max_fault_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 12),
                        KCSubTypeElement.FromBasicCtype('sfs_stopped_faulting', KCSUBTYPE_TYPE.KC_ST_UINT8, 20)
            ),
            'stackshot_fault_stats')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_WAITINFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_THREAD_WAITINFO'),
            (
                        KCSubTypeElement.FromBasicCtype('owner', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('waiter', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('context', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
                        KCSubTypeElement.FromBasicCtype('wait_type', KCSUBTYPE_TYPE.KC_ST_UINT8, 24),
                        KCSubTypeElement.FromBasicCtype('portlabel_id', KCSUBTYPE_TYPE.KC_ST_INT16, 25),
                        KCSubTypeElement.FromBasicCtype('wait_flags', KCSUBTYPE_TYPE.KC_ST_INT32, 27)
            ),
            'thread_waitinfo')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_TURNSTILEINFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_THREAD_TURNSTILEINFO'),
            (
                        KCSubTypeElement.FromBasicCtype('waiter', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('turnstile_context', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('turnstile_priority', KCSUBTYPE_TYPE.KC_ST_UINT8, 16),
                        KCSubTypeElement.FromBasicCtype('number_of_hops', KCSUBTYPE_TYPE.KC_ST_UINT8, 17),
                        KCSubTypeElement.FromBasicCtype('turnstile_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 18),
                        KCSubTypeElement.FromBasicCtype('portlabel_id', KCSUBTYPE_TYPE.KC_ST_INT16, 26),
            ),
            'thread_turnstileinfo')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_PORTLABEL')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_PORTLABEL'),
            (
                        KCSubTypeElement.FromBasicCtype('portlabel_id', KCSUBTYPE_TYPE.KC_ST_INT16, 0),
                        KCSubTypeElement.FromBasicCtype('portlabel_flags', KCSUBTYPE_TYPE.KC_ST_UINT16, 2),
                        KCSubTypeElement.FromBasicCtype('portlabel_domain', KCSUBTYPE_TYPE.KC_ST_UINT8, 4),
            ),
            'portlabel_info', merge=True)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_PORTLABEL_NAME')] = (
    KCSubTypeElement("portlabel_name", KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(-1, 1), 0, 1))

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_GROUP_SNAPSHOT')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_THREAD_GROUP'),
            (
                        KCSubTypeElement.FromBasicCtype('tgs_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement('tgs_name', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(16, 1),
                            8, 1),
                        KCSubTypeElement.FromBasicCtype('tgs_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
            ),
            'thread_group_snapshot')


KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_GROUP')] = KCSubTypeElement('thread_group', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_JETSAM_COALITION_SNAPSHOT')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_JETSAM_COALITION_SNAPSHOT'),
            (
                        KCSubTypeElement.FromBasicCtype('jcs_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('jcs_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('jcs_thread_group', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
                        KCSubTypeElement.FromBasicCtype('jcs_leader_task_uniqueid', KCSUBTYPE_TYPE.KC_ST_UINT64, 24)
            ),
            'jetsam_coalition_snapshot')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_JETSAM_COALITION')] = KCSubTypeElement('jetsam_coalition', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_INSTRS_CYCLES')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_INSTRS_CYCLES'),
            (
                        KCSubTypeElement.FromBasicCtype('ics_instructions', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('ics_cycles', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('ics_p_instructions', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
                        KCSubTypeElement.FromBasicCtype('ics_p_cycles', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
            ),
            'instrs_cycles_snapshot')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_TASK_CPU_ARCHITECTURE')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_TASK_CPU_ARCHITECTURE'),
            (
                        KCSubTypeElement.FromBasicCtype('cputype', KCSUBTYPE_TYPE.KC_ST_INT32, 0),
                        KCSubTypeElement.FromBasicCtype('cpusubtype', KCSUBTYPE_TYPE.KC_ST_INT32, 4)
            ),
            'task_cpu_architecture')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_LATENCY_INFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_LATENCY_INFO'),
            (
                        KCSubTypeElement.FromBasicCtype('latency_version', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('setup_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('total_task_iteration_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
                        KCSubTypeElement.FromBasicCtype('total_terminated_task_iteration', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
                        KCSubTypeElement.FromBasicCtype('task_queue_building_latency_mt', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
                        KCSubTypeElement.FromBasicCtype('terminated_task_queue_building_latency_mt', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
                        KCSubTypeElement.FromBasicCtype('cpu_wait_latency_mt', KCSUBTYPE_TYPE.KC_ST_INT32, 48),
                        KCSubTypeElement.FromBasicCtype('calling_cpu_number', KCSUBTYPE_TYPE.KC_ST_INT32, 56),
            ),
            'stackshot_latency_collection')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_LATENCY_INFO_CPU')] = KCTypeDescription(GetTypeForName('STACKSHOT_LATENCY_INFO_CPU'),
            (
                        KCSubTypeElement.FromBasicCtype('cpu_number', KCSUBTYPE_TYPE.KC_ST_INT32, 0),
                        KCSubTypeElement.FromBasicCtype('cluster_type', KCSUBTYPE_TYPE.KC_ST_INT32, 4),
                        KCSubTypeElement.FromBasicCtype('init_latency_mt', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('workqueue_latency_mt', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
                        KCSubTypeElement.FromBasicCtype('total_latency_mt', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
                        KCSubTypeElement.FromBasicCtype('total_cycles', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
                        KCSubTypeElement.FromBasicCtype('total_instrs', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
                        KCSubTypeElement.FromBasicCtype('tasks_processed', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
                        KCSubTypeElement.FromBasicCtype('threads_processed', KCSUBTYPE_TYPE.KC_ST_UINT64, 56),
                        KCSubTypeElement.FromBasicCtype('faulting_time_mt', KCSUBTYPE_TYPE.KC_ST_UINT64, 64),
                        KCSubTypeElement.FromBasicCtype('total_buf', KCSUBTYPE_TYPE.KC_ST_UINT64, 72),
                        KCSubTypeElement.FromBasicCtype('intercluster_buf_used', KCSUBTYPE_TYPE.KC_ST_UINT64, 80),
            ),
            'stackshot_latency_cpu')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_LATENCY_INFO_TASK')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_LATENCY_INFO_TASK'),
            (
                        KCSubTypeElement.FromBasicCtype('task_uniqueid', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('setup_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('task_thread_count_loop_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
                        KCSubTypeElement.FromBasicCtype('task_thread_data_loop_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
                        KCSubTypeElement.FromBasicCtype('cur_tsnap_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
                        KCSubTypeElement.FromBasicCtype('pmap_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
                        KCSubTypeElement.FromBasicCtype('bsd_proc_ids_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
                        KCSubTypeElement.FromBasicCtype('misc_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 56),
                        KCSubTypeElement.FromBasicCtype('misc2_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 64),
                        KCSubTypeElement.FromBasicCtype('end_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 72)
            ),
            'stackshot_latency_task')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_LATENCY_INFO_THREAD')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_LATENCY_INFO_THREAD'),
            (
                        KCSubTypeElement.FromBasicCtype('thread_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('cur_thsnap1_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('dispatch_serial_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
                        KCSubTypeElement.FromBasicCtype('dispatch_label_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
                        KCSubTypeElement.FromBasicCtype('cur_thsnap2_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
                        KCSubTypeElement.FromBasicCtype('thread_name_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
                        KCSubTypeElement.FromBasicCtype('sur_times_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
                        KCSubTypeElement.FromBasicCtype('user_stack_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 56),
                        KCSubTypeElement.FromBasicCtype('kernel_stack_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 64),
                        KCSubTypeElement.FromBasicCtype('misc_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 72),
            ),
            'stackshot_latency_thread')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_NAME')] = KCSubTypeElement('pth_name', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(64, 1), 0, 1)

def set_type(name, *args):
    typ = GetTypeForName(name)
    KNOWN_TYPES_COLLECTION[typ] = KCTypeDescription(GetTypeForName(typ), *args)


set_type('STACKSHOT_KCTYPE_USER_STACKTOP',
         (
             KCSubTypeElement.FromBasicCtype('sp', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
             KCSubTypeElement('stack_contents', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(8, 1), 8, 1),
         ),
         'user_stacktop')

#KNOWN_TYPES_COLLECTION[0x907] = KCSubTypeElement('donating_pids', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0, KCSubTypeElement._get_naked_element_value)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PID')] = KCSubTypeElement('pid', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PPID')] = KCSubTypeElement('ppid', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_NAME')] = KCSubTypeElement('p_comm', KCSUBTYPE_TYPE.KC_ST_CHAR,
                           KCSubTypeElement.GetSizeForArray(32, 1), 0, 1)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_USERSTACK')] = KCSubTypeElement('userstack_ptr', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_ARGSLEN')] = KCSubTypeElement('p_argslen', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_PATH')] = KCSubTypeElement('p_path', KCSUBTYPE_TYPE.KC_ST_CHAR,
                           KCSubTypeElement.GetSizeForArray(1024, 1), 0, 1)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_CSFLAGS')] = KCSubTypeElement('p_csflags', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_UID')] = KCSubTypeElement('uid', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_GID')] = KCSubTypeElement('gid', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_ARGC')] = KCSubTypeElement('argc', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_FLAGS')] = KCSubTypeElement('p_flags', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_CPUTYPE')] = KCSubTypeElement('cputype', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_RESPONSIBLE_PID')] = KCSubTypeElement('responsible_pid', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_DIRTY_FLAGS')] = KCSubTypeElement('dirty_flags', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_CRASHED_THREADID')] = KCSubTypeElement('crashed_threadid', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_COALITION_ID')] = KCSubTypeElement('coalition_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0)

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_STATUS')] = KCSubTypeElement('p_status', KCSUBTYPE_TYPE.KC_ST_UINT8, 1, 0, 0)

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_BSDINFOWITHUNIQID')] = KCTypeDescription(GetTypeForName('TASK_CRASHINFO_BSDINFOWITHUNIQID'),
    (   KCSubTypeElement('p_uuid', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 0, 1),
        KCSubTypeElement.FromBasicCtype('p_uniqueid', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
        KCSubTypeElement.FromBasicCtype('p_puniqueid', KCSUBTYPE_TYPE.KC_ST_UINT64, 24)
    ),
    'proc_uniqidentifierinfo')

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_EXCEPTION_CODES')] = (
    KCTypeDescription(GetTypeForName('TASK_CRASHINFO_EXCEPTION_CODES'),
                      (KCSubTypeElement.FromBasicCtype('code_0', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                       KCSubTypeElement.FromBasicCtype('code_1', KCSUBTYPE_TYPE.KC_ST_UINT64, 8)),
                      'mach_exception_data_t'))


KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_STARTTIME')] = (
    KCTypeDescription(GetTypeForName('TASK_CRASHINFO_PROC_STARTTIME'),
                      (KCSubTypeElement.FromBasicCtype('tv_sec', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                       KCSubTypeElement.FromBasicCtype('tv_usec', KCSUBTYPE_TYPE.KC_ST_UINT64, 8)),
                      'proc_starttime'))


KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_RUSAGE_INFO')] = KCTypeDescription(GetTypeForName('TASK_CRASHINFO_RUSAGE_INFO'),
    (
        KCSubTypeElement('ri_uuid', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 0, 1),
            KCSubTypeElement.FromBasicCtype('ri_user_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
            KCSubTypeElement.FromBasicCtype('ri_system_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
            KCSubTypeElement.FromBasicCtype('ri_pkg_idle_wkups', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
            KCSubTypeElement.FromBasicCtype('ri_interrupt_wkups', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
            KCSubTypeElement.FromBasicCtype('ri_pageins', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
            KCSubTypeElement.FromBasicCtype('ri_wired_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 56),
            KCSubTypeElement.FromBasicCtype('ri_resident_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 64),
            KCSubTypeElement.FromBasicCtype('ri_phys_footprint', KCSUBTYPE_TYPE.KC_ST_UINT64, 72),
            KCSubTypeElement.FromBasicCtype('ri_proc_start_abstime', KCSUBTYPE_TYPE.KC_ST_UINT64, 80),
            KCSubTypeElement.FromBasicCtype('ri_proc_exit_abstime', KCSUBTYPE_TYPE.KC_ST_UINT64, 88),
            KCSubTypeElement.FromBasicCtype('ri_child_user_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 96),
            KCSubTypeElement.FromBasicCtype('ri_child_system_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 104),
            KCSubTypeElement.FromBasicCtype('ri_child_pkg_idle_wkups', KCSUBTYPE_TYPE.KC_ST_UINT64, 112),
            KCSubTypeElement.FromBasicCtype('ri_child_interrupt_wkups', KCSUBTYPE_TYPE.KC_ST_UINT64, 120),
            KCSubTypeElement.FromBasicCtype('ri_child_pageins', KCSUBTYPE_TYPE.KC_ST_UINT64, 128),
            KCSubTypeElement.FromBasicCtype('ri_child_elapsed_abstime', KCSUBTYPE_TYPE.KC_ST_UINT64, 136),
            KCSubTypeElement.FromBasicCtype('ri_diskio_bytesread', KCSUBTYPE_TYPE.KC_ST_UINT64, 144),
            KCSubTypeElement.FromBasicCtype('ri_diskio_byteswritten', KCSUBTYPE_TYPE.KC_ST_UINT64, 152),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_default', KCSUBTYPE_TYPE.KC_ST_UINT64, 160),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_maintenance', KCSUBTYPE_TYPE.KC_ST_UINT64, 168),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_background', KCSUBTYPE_TYPE.KC_ST_UINT64, 176),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_utility', KCSUBTYPE_TYPE.KC_ST_UINT64, 184),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_legacy', KCSUBTYPE_TYPE.KC_ST_UINT64, 192),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_user_initiated', KCSUBTYPE_TYPE.KC_ST_UINT64, 200),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_user_interactiv', KCSUBTYPE_TYPE.KC_ST_UINT64, 208),
            KCSubTypeElement.FromBasicCtype('ri_billed_system_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 216),
            KCSubTypeElement.FromBasicCtype('ri_serviced_system_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 224)
    ),
    'rusage_info')

#The sizes for these need to be kept in sync with
#MAX_CRASHINFO_SIGNING_ID_LEN, MAX_CRASHINFO_TEAM_ID_LEN
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_CS_SIGNING_ID')] = KCSubTypeElement('cs_signing_id', KCSUBTYPE_TYPE.KC_ST_CHAR,
                           KCSubTypeElement.GetSizeForArray(64, 1), 0, 1)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_CS_TEAM_ID')] = KCSubTypeElement('cs_team_id', KCSUBTYPE_TYPE.KC_ST_CHAR,
                           KCSubTypeElement.GetSizeForArray(32, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_CS_VALIDATION_CATEGORY')] = KCSubTypeElement('cs_validation_category', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0)

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_CS_TRUST_LEVEL')] = KCSubTypeElement('cs_trust_level', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0)

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_JIT_ADDRESS_RANGE')] = KCTypeDescription(GetTypeForName('TASK_CRASHINFO_JIT_ADDRESS_RANGE'),
    (
        KCSubTypeElement.FromBasicCtype('start_address', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
        KCSubTypeElement.FromBasicCtype('end_address', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    ), 'jit_address_range')

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_MB')] = KCTypeDescription(GetTypeForName('TASK_CRASHINFO_MB'),
    (
        KCSubTypeElement.FromBasicCtype('start_address', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
        KCSubTypeElement('data', KCSUBTYPE_TYPE.KC_ST_UINT64, KCSubTypeElement.GetSizeForArray(64, 64), 8, 0),
    )
)

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_CS_AUXILIARY_INFO')] = KCSubTypeElement('cs_auxiliary_info', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_CPU_TIMES')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_CPU_TIMES'),
    (
        KCSubTypeElement.FromBasicCtype('user_usec', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
        KCSubTypeElement.FromBasicCtype('system_usec', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
        KCSubTypeElement.FromBasicCtype('runnable_usec', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    ), 'cpu_times')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_STACKSHOT_DURATION')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_STACKSHOT_DURATION'),
    (
        KCSubTypeElement.FromBasicCtype('stackshot_duration', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
        KCSubTypeElement.FromBasicCtype('stackshot_duration_outer', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
        KCSubTypeElement.FromBasicCtype('stackshot_duration_prior', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    ), 'stackshot_duration', merge=True
)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_PROCNAME')] = (
    KCSubTypeElement("proc_name", KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(-1, 1), 0, 1))

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_PID')] = (
    KCSubTypeElement('pid', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0))

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_LIBRARY_AOTINFO')] = KCTypeDescription(GetTypeForName('KCDATA_TYPE_LIBRARY_AOTINFO'),
    (
        KCSubTypeElement('x86LoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
        KCSubTypeElement('aotLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 8, 0),
        KCSubTypeElement('aotImageSize', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 16, 0),
        KCSubTypeElement('aotImageKey', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(32, 1), 24, 1),
    ), 'dyld_aot_info')

KNOWN_TYPES_COLLECTION[GetTypeForName('EXIT_REASON_SNAPSHOT')] = KCTypeDescription(GetTypeForName('EXIT_REASON_SNAPSHOT'),
    (
        KCSubTypeElement.FromBasicCtype('ers_namespace', KCSUBTYPE_TYPE.KC_ST_UINT32, 0),
        KCSubTypeElement.FromBasicCtype('ers_code', KCSUBTYPE_TYPE.KC_ST_UINT64, 4),
        KCSubTypeElement.FromBasicCtype('ers_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 12),
    ), 'exit_reason_basic_info')

KNOWN_TYPES_COLLECTION[GetTypeForName('EXIT_REASON_USER_DESC')] = (
    KCSubTypeElement("exit_reason_user_description", KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(-1, 1), 0, 1))

KNOWN_TYPES_COLLECTION[GetTypeForName('EXIT_REASON_USER_PAYLOAD')] = KCSubTypeElement('exit_reason_user_payload',
        KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(-1, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('EXIT_REASON_CODESIGNING_INFO')] = KCTypeDescription(GetTypeForName('EXIT_REASON_CODESIGNING_INFO'),
    (
        KCSubTypeElement.FromBasicCtype('ceri_virt_addr', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
        KCSubTypeElement.FromBasicCtype('ceri_file_offset', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
        KCSubTypeElement("ceri_pathname", KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(1024, 1), 16, 1),
        KCSubTypeElement("ceri_filename", KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(1024, 1), 1040, 1),
        KCSubTypeElement.FromBasicCtype('ceri_codesig_modtime_secs', KCSUBTYPE_TYPE.KC_ST_UINT64, 2064),
        KCSubTypeElement.FromBasicCtype('ceri_codesig_modtime_nsecs', KCSUBTYPE_TYPE.KC_ST_UINT64, 2072),
        KCSubTypeElement.FromBasicCtype('ceri_page_modtime_secs', KCSUBTYPE_TYPE.KC_ST_UINT64, 2080),
        KCSubTypeElement.FromBasicCtype('ceri_page_modtime_nsecs', KCSUBTYPE_TYPE.KC_ST_UINT64, 2088),
        KCSubTypeElement.FromBasicCtype('ceri_path_truncated', KCSUBTYPE_TYPE.KC_ST_UINT8, 2096),
        KCSubTypeElement.FromBasicCtype('ceri_object_codesigned', KCSUBTYPE_TYPE.KC_ST_UINT8, 2097),
        KCSubTypeElement.FromBasicCtype('ceri_page_codesig_validated', KCSUBTYPE_TYPE.KC_ST_UINT8, 2098),
        KCSubTypeElement.FromBasicCtype('ceri_page_codesig_tainted', KCSUBTYPE_TYPE.KC_ST_UINT8, 2099),
        KCSubTypeElement.FromBasicCtype('ceri_page_codesig_nx', KCSUBTYPE_TYPE.KC_ST_UINT8, 2100),
        KCSubTypeElement.FromBasicCtype('ceri_page_wpmapped', KCSUBTYPE_TYPE.KC_ST_UINT8, 2101),
        KCSubTypeElement.FromBasicCtype('ceri_page_slid', KCSUBTYPE_TYPE.KC_ST_UINT8, 2102),
        KCSubTypeElement.FromBasicCtype('ceri_page_dirty', KCSUBTYPE_TYPE.KC_ST_UINT8, 2103),
        KCSubTypeElement.FromBasicCtype('ceri_page_shadow_depth', KCSUBTYPE_TYPE.KC_ST_UINT32, 2104),
    ), 'exit_reason_codesigning_info')

KNOWN_TYPES_COLLECTION[GetTypeForName('EXIT_REASON_WORKLOOP_ID')] = (
        KCSubTypeElement('exit_reason_workloop_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value))

KNOWN_TYPES_COLLECTION[GetTypeForName('EXIT_REASON_DISPATCH_QUEUE_NO')] = (
        KCSubTypeElement('exit_reason_dispatch_queue_no', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value))

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_ASID')] = (
    KCSubTypeElement('ts_asid', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0))

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_PAGE_TABLES')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_PAGE_TABLES'), (
    KCSubTypeElement(None, KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value), ),
    'ts_pagetable',
    merge=True,
    naked=True
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_SUSPENSION_INFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_SUSPENSION_INFO'), (
    KCSubTypeElement.FromBasicCtype('tss_last_start', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('tss_last_end', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('tss_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('tss_duration', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
), 'suspension_info')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_SUSPENSION_SOURCE')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_SUSPENSION_SOURCE'), (
    KCSubTypeElement.FromBasicCtype('tss_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('tss_tid', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('tss_pid', KCSUBTYPE_TYPE.KC_ST_INT32, 16),
    KCSubTypeElement('tss_procname', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(65, 1), 20, 1)
), 'suspension_source')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_OS_BUILD_VERSION')] = KCSubTypeElement('os_build_version', KCSUBTYPE_TYPE.KC_ST_CHAR,
                          KCSubTypeElement.GetSizeForArray(256, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_EXCLAVES_THREADINFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_KERN_EXCLAVES_THREADINFO'),
    (
        KCSubTypeElement.FromBasicCtype('tei_scid', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
        KCSubTypeElement.FromBasicCtype('tei_thread_offset', KCSUBTYPE_TYPE.KC_ST_UINT32, 8),
        KCSubTypeElement.FromBasicCtype('tei_flags', KCSUBTYPE_TYPE.KC_ST_UINT32, 12),
    ), 'exclaves_thread_info')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_EXCLAVE_SCRESULT_INFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_EXCLAVE_SCRESULT_INFO'),
    (
        KCSubTypeElement.FromBasicCtype('esc_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
        KCSubTypeElement.FromBasicCtype('esc_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    ), 'exclave_scresult_info')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_EXCLAVE_IPCSTACKENTRY_INFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_EXCLAVE_IPCSTACKENTRY_INFO'),
    (
        KCSubTypeElement.FromBasicCtype('eise_asid', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
        KCSubTypeElement.FromBasicCtype('eise_tnid', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
        KCSubTypeElement.FromBasicCtype('eise_invocationid', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
        KCSubTypeElement.FromBasicCtype('eise_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    ), 'exclave_ipcstackentry_info')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_EXCLAVE_IPCSTACKENTRY_ECSTACK')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_EXCLAVE_IPCSTACKENTRY_ECSTACK'),
    (
        KCSubTypeElement.FromBasicCtype('lr', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    ), 'secure_ecstack_entry')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_EXCLAVE_ADDRESSSPACE_INFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_EXCLAVE_ADDRESSSPACE_INFO'),
    (
        KCSubTypeElement.FromBasicCtype('eas_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
        KCSubTypeElement.FromBasicCtype('eas_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
        KCSubTypeElement.FromBasicCtype('eas_layoutid', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
        KCSubTypeElement.FromBasicCtype('eas_slide', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
        KCSubTypeElement.FromBasicCtype('eas_asroot', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
    ), 'exclave_addressspace_info')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_EXCLAVE_ADDRESSSPACE_NAME')] = KCSubTypeElement('exclave_addressspace_name', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(64, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_INFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_INFO'),
    (
        KCSubTypeElement.FromBasicCtype('layout_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
        KCSubTypeElement.FromBasicCtype('etl_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
        KCSubTypeElement.FromBasicCtype('sharedcache_index', KCSUBTYPE_TYPE.KC_ST_UINT32, 16),
    ), 'exclave_textlayout_info')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_SEGMENTS')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_SEGMENTS'),
    (
        KCSubTypeElement('layoutSegment_uuid', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 0, 1),
        KCSubTypeElement.FromBasicCtype('layoutSegment_loadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
        KCSubTypeElement.FromBasicCtype('layoutSegment_rawLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    ), 'exclave_textlayout_segments')

def GetSecondsFromMATime(mat, tb):
    return (float(long(mat) * tb['numer']) / tb['denom']) / 1e9

def GetLongForAddress(address):
    if isinstance(address, str):
        if '0x' in address.lower():
            address = long(address, 16)
        else:
            address = long(address)
    return address

def FindLibraryForAddress(liblist, address):
    current_lib = None
    for l in liblist:
        l_addr = GetLongForAddress(l[1])
        if address >= l_addr:
            current_lib = l
    return current_lib

def FindIndexOfLibInCatalog(catalog, lib):
    index = None
    i = 0
    for l in catalog:
        if l[0] == lib[0] and l[1] == lib[1]:
            index = i
            break
        i += 1

    if index is None:
        catalog.append(lib)
        index = len(catalog) - 1

    return index

def GetOffsetOfAddressForLib(lib, address):
    return (address - GetLongForAddress(lib[1]))

def GetSymbolInfoForFrame(catalog, liblist, address):
    address = GetLongForAddress(address)
    lib = FindLibraryForAddress(liblist, address)
    if not lib:
        lib = ["00000000000000000000000000000000",0,"A"]
    offset = GetOffsetOfAddressForLib(lib, address)
    index = FindIndexOfLibInCatalog(catalog, lib)
    return [index, offset]

def GetStateDescription(s):
    retval = []
    TH_WAIT = 0x01
    TH_SUSP = 0x02
    TH_RUN = 0x04
    TH_UNINT = 0x08
    TH_TERMINATE = 0x10
    TH_TERMINATE2 = 0x20
    TH_WAIT_REPORT = 0x40
    TH_IDLE = 0x80
    if (s & TH_WAIT):
        retval.append("TH_WAIT")
    if (s & TH_SUSP):
        retval.append("TH_SUSP")
    if (s & TH_RUN):
        retval.append("TH_RUN")
    if (s & TH_UNINT):
        retval.append("TH_UNINT")
    if (s & TH_TERMINATE):
        retval.append("TH_TERMINATE")
    if (s & TH_TERMINATE2):
        retval.append("TH_TERMINATE2")
    if (s & TH_WAIT_REPORT):
        retval.append("TH_WAIT_REPORT")
    if (s & TH_IDLE):
        retval.append("TH_IDLE")
    return retval


def format_uuid(elementValues):
    # sometimes we get string like "25A926D8-F742-3E5E..."
    if isinstance(elementValues, str):
        return elementValues
    return ''.join("%02x" % i for i in elementValues)

kThreadWaitNone                 = 0x00
kThreadWaitKernelMutex          = 0x01
kThreadWaitPortReceive          = 0x02
kThreadWaitPortSetReceive       = 0x03
kThreadWaitPortSend             = 0x04
kThreadWaitPortSendInTransit    = 0x05
kThreadWaitSemaphore            = 0x06
kThreadWaitKernelRWLockRead     = 0x07
kThreadWaitKernelRWLockWrite    = 0x08
kThreadWaitKernelRWLockUpgrade  = 0x09
kThreadWaitUserLock             = 0x0a
kThreadWaitPThreadMutex         = 0x0b
kThreadWaitPThreadRWLockRead    = 0x0c
kThreadWaitPThreadRWLockWrite   = 0x0d
kThreadWaitPThreadCondVar       = 0x0e
kThreadWaitParkedWorkQueue      = 0x0f
kThreadWaitWorkloopSyncWait     = 0x10
kThreadWaitOnProcess            = 0x11
kThreadWaitSleepWithInheritor   = 0x12
kThreadWaitEventlink            = 0x13
kThreadWaitCompressor           = 0x14
kThreadWaitParkedBoundWorkQueue = 0x15
kThreadWaitPageBusy             = 0x16
kThreadWaitPagerInit            = 0x17
kThreadWaitPagerReady           = 0x18
kThreadWaitPagingActivity       = 0x19
kThreadWaitMappingInProgress    = 0x1a
kThreadWaitMemoryBlocked        = 0x1b
kThreadWaitPagingInProgress     = 0x1c
kThreadWaitPageInThrottle       = 0x1d
kThreadWaitExclaveCore          = 0x1e
kThreadWaitExclaveKit           = 0x1f


UINT64_MAX = 0xffffffffffffffff
STACKSHOT_WAITOWNER_KERNEL      = (UINT64_MAX - 1)
STACKSHOT_WAITOWNER_PORT_LOCKED = (UINT64_MAX - 2)
STACKSHOT_WAITOWNER_PSET_LOCKED = (UINT64_MAX - 3)
STACKSHOT_WAITOWNER_INTRANSIT   = (UINT64_MAX - 4)
STACKSHOT_WAITOWNER_MTXSPIN     = (UINT64_MAX - 5)
STACKSHOT_WAITOWNER_THREQUESTED = (UINT64_MAX - 6)
STACKSHOT_WAITOWNER_SUSPENDED   = (UINT64_MAX - 7)

STACKSHOT_TURNSTILE_STATUS_UNKNOWN         = 0x01
STACKSHOT_TURNSTILE_STATUS_LOCKED_WAITQ    = 0x02
STACKSHOT_TURNSTILE_STATUS_WORKQUEUE       = 0x04
STACKSHOT_TURNSTILE_STATUS_THREAD          = 0x08
STACKSHOT_TURNSTILE_STATUS_BLOCKED_ON_TASK = 0x10
STACKSHOT_TURNSTILE_STATUS_HELD_IPLOCK     = 0x20
STACKSHOT_TURNSTILE_STATUS_SENDPORT        = 0x40
STACKSHOT_TURNSTILE_STATUS_RECEIVEPORT     = 0x80

#
# These come from xpc_domain_type_t in <xpc/launch_private.h>
PORTLABEL_DOMAINS = {
    1: 'system',        # XPC_DOMAIN_SYSTEM
    2: 'user',          # XPC_DOMAIN_USER
    5: 'pid',           # XPC_DOMAIN_PID
    7: 'port',          # XPC_DOMAIN_PORT
}
def portlabel_domain(x):
    if x is None:
        return "unknown"
    return PORTLABEL_DOMAINS.get(x, "unknown.{}".format(x))

STACKSHOT_WAITINFO_FLAGS_SPECIALREPLY = 0x1
STACKSHOT_PORTLABEL_THROTTLED = 0x2

def portThrottledSuffix(portlabel_flags):
    if (portlabel_flags & STACKSHOT_PORTLABEL_THROTTLED):
        return " (service port throttled by launchd)"
    else:
        return ""

def formatPortLabelID(portlabel_id, portlabels):
    portlabel = {}
    if portlabel_id > 0:
        if portlabels is not None:
            portlabel = portlabels.get(str(portlabel_id), {})
        portlabel_name = portlabel_domain(portlabel.get('portlabel_domain')) + " "
        portlabel_name += portlabel.get("portlabel_name", "!!!unknown, ID {} !!!".format(portlabel_id));
        return " {" + portlabel_name + portThrottledSuffix(portlabel.get('portlabel_flags', 0)) + "}"
    if portlabel_id < 0:
        return " {labeled, info truncated" + portThrottledSuffix(portlabel.get('portlabel_flags', 0)) + "}"
    return ""

def formatWaitInfo(info, wantHex, portlabels):
    base='#x' if wantHex else 'd'
    s = 'thread {0:{base}}: '.format(info['waiter'], base=base)
    type = info['wait_type']
    context = info['context']
    owner = info['owner']
    ownerThread = "{0:{base}}".format(owner, base=base)
    portlabel_id = info.get('portlabel_id', 0)
    flags = info.get('wait_flags', 0)

    if type == kThreadWaitKernelMutex:
        s += 'kernel mutex %x' % context
        if owner == STACKSHOT_WAITOWNER_MTXSPIN:
            s += " in spin mode"
        elif owner:
            s += " owned by thread %s" % ownerThread
        else:
            s += "with unknown owner"
    elif type == kThreadWaitPortReceive:
        s += "mach_msg receive on "
        if flags & STACKSHOT_WAITINFO_FLAGS_SPECIALREPLY:
            s += "REPLY "
            flags = flags - STACKSHOT_WAITINFO_FLAGS_SPECIALREPLY
        if owner == STACKSHOT_WAITOWNER_PORT_LOCKED:
            s += "locked port %x" % context
        elif owner == STACKSHOT_WAITOWNER_INTRANSIT:
            s += "intransit port %x" % context
        elif owner:
            s += "port %x name %x" % (context, owner)
        else:
            s += "port %x" % context
    elif type == kThreadWaitPortSetReceive:
        if owner == STACKSHOT_WAITOWNER_PSET_LOCKED:
            s += "mach_msg receive on locked port set %x" % context
        else:
            s += "mach_msg receive on port set %x" % context
    elif type == kThreadWaitPortSend:
        s += "mach_msg send on "
        if owner == STACKSHOT_WAITOWNER_PORT_LOCKED:
            s += "locked port %x" % context
        elif owner == STACKSHOT_WAITOWNER_INTRANSIT:
            s += "intransit port %x" % context
        elif owner == STACKSHOT_WAITOWNER_KERNEL:
            s += "port %x owned by kernel" % context
        elif owner:
            s += "port %x owned by pid %d" % (context, owner)
        else:
            s += "port %x with unknown owner" % context
    elif type == kThreadWaitPortSendInTransit:
        s += "mach_msg send on port %x in transit to " % context
        if owner:
            s += "port %x" % owner
        else:
            s += "unknown port"
    elif type == kThreadWaitSemaphore:
        s += "semaphore port %x " % context
        if owner:
            s += "owned by pid %d" % owner
        else:
            s += "with unknown owner"
    elif type == kThreadWaitKernelRWLockRead:
        s += "krwlock %x for reading" % context
        if owner:
            s += " owned by thread %s" % ownerThread
    elif type == kThreadWaitKernelRWLockWrite:
        s += "krwlock %x for writing" % context
        if owner:
            s += " owned by thread %s" % ownerThread
    elif type == kThreadWaitKernelRWLockUpgrade:
        s += "krwlock %x for upgrading" % context
        if owner:
            s += " owned by thread %s" % ownerThread
    elif type == kThreadWaitUserLock:
        if owner:
            s += "unfair lock %x owned by thread %s" % (context, ownerThread)
        else:
            s += "spin lock %x" % context
    elif type == kThreadWaitPThreadMutex:
        s += "pthread mutex %x" % context
        if owner:
            s += " owned by thread %s" % ownerThread
        else:
            s += " with unknown owner"
    elif type == kThreadWaitPThreadRWLockRead:
        s += "pthread rwlock %x for reading" % context
    elif type == kThreadWaitPThreadRWLockWrite:
        s += "pthread rwlock %x for writing" % context
    elif type == kThreadWaitPThreadCondVar:
        s += "pthread condvar %x" % context
    elif type == kThreadWaitWorkloopSyncWait:
        s += "workloop sync wait"
        if owner == STACKSHOT_WAITOWNER_SUSPENDED:
            s += ", suspended"
        elif owner == STACKSHOT_WAITOWNER_THREQUESTED:
            s += ", thread requested"
        elif owner != 0:
            s += ", owned by thread %s" % ownerThread
        else:
            s += ", unknown owner"
        s += ", workloop id %x" % context
    elif type == kThreadWaitOnProcess:
        if owner == 2**64-1:
            s += "waitpid, for any children"
        elif 2**32 <= owner and owner < 2**64-1:
            s += "waitpid, for process group %d" % abs(owner - 2**64)
        else:
            s += "waitpid, for pid %d" % owner
    elif type == kThreadWaitSleepWithInheritor:
        if owner == 0:
            s += "turnstile, held waitq"
        else:
            s += "turnstile, pushing thread %s" % ownerThread
    elif type == kThreadWaitEventlink:
        if owner == 0:
            s += "eventlink, held waitq"
        else:
            s += "eventlink, signaled by thread %s" % ownerThread
    elif type == kThreadWaitCompressor:
        s += "in compressor segment %x, busy for thread %s" % (context, ownerThread)
    elif type == kThreadWaitExclaveCore:
        if owner == 0:
            s += "exclavecore wait, id 0x%x" % context
        else:
            s += "exclavecore wait, id 0x%x, owner thread %s" % (context, ownerThread)
    elif type == kThreadWaitExclaveKit:
        if owner == 0:
            s += "exclavekit wait, id 0x%x" % context
        else:
            s += "exclavekit wait, id 0x%x, owner thread %s" % (context, ownerThread)
    elif type == kThreadWaitPageBusy:
        s += f"busy page 0x{context:x}"
    elif type == kThreadWaitPagerInit:
        s += f"pager initialization for vm object 0x{context:x}"
    elif type == kThreadWaitPagerReady:
        s += f"pager ready for vm object 0x{context:x}"
    elif type == kThreadWaitPagingActivity:
        s += f"paging/activity in progress for vm object 0x{context:x}"
    elif type == kThreadWaitMappingInProgress:
        s += f"mapping in progress for vm object 0x{context:x}"
    elif type == kThreadWaitMemoryBlocked:
        s += f"blocked vm object 0x{context:x}"
    elif type == kThreadWaitPagingInProgress:
        s += f"paging in progress for vm object 0x{context:x}"
    elif type == kThreadWaitPageInThrottle:
        s += f"throttled vm object 0x{context:x}"
    else:
        s += "unknown type %d (owner %s, context %x)" % (type, ownerThread, context)

    s += formatPortLabelID(portlabel_id, portlabels)

    if flags != 0:
        s += "flags {}".format(hex(flags))
    return s

def formatTurnstileInfo(ti, wi_portlabel_id, portlabels):
    if ti is None:
        return " [no turnstile]"

    ts_flags = int(ti['turnstile_flags'])
    ctx = int(ti['turnstile_context'])
    hop = int(ti['number_of_hops'])
    prio = int(ti['turnstile_priority'])
    portlabel_id = ti.get("portlabel_id", 0)

    portlabel_summary = ""
    if portlabel_id != 0 and portlabel_id != wi_portlabel_id:
        portlabel_summary += formatPortLabelID(portlabel_id, portlabels)

    if ts_flags & STACKSHOT_TURNSTILE_STATUS_HELD_IPLOCK:
        return " [turnstile blocked on task, but ip_lock was held]" + portlabel_summary
    if ts_flags & STACKSHOT_TURNSTILE_STATUS_BLOCKED_ON_TASK:
        return " [turnstile blocked on task pid %d, hops: %d, priority: %d]%s" % (ctx, hop, prio, portlabel_summary)
    if ts_flags & STACKSHOT_TURNSTILE_STATUS_LOCKED_WAITQ:
        return " [turnstile was in process of being updated]" + portlabel_summary
    if ts_flags & STACKSHOT_TURNSTILE_STATUS_WORKQUEUE:
        return " [blocked on workqueue: 0x%x, hops: %x, priority: %d]%s" % (ctx, hop, prio, portlabel_summary)
    if ts_flags & STACKSHOT_TURNSTILE_STATUS_THREAD:
        return " [blocked on: %d, hops: %x, priority: %d]%s" % (ctx, hop, prio, portlabel_summary)
    if ts_flags & STACKSHOT_TURNSTILE_STATUS_UNKNOWN:
        return " [turnstile with unknown inheritor]" + portlabel_summary

    return " [unknown turnstile status!]" + portlabel_summary

def formatWaitInfoWithTurnstiles(waitinfos, tsinfos, portlabels):
    wis_tis = []
    for w in waitinfos:
        found_pair = False
        for t in tsinfos:
            if int(w['waiter']) == int(t['waiter']):
                wis_tis.append((w, t))
                found_pair = True
                break
        if not found_pair:
            wis_tis.append((w, None))

    return [formatWaitInfo(wi, False, portlabels) + formatTurnstileInfo(ti, wi.get('portlabel_id', 0), portlabels) for (wi, ti) in wis_tis]


def FindTextLayout(text_layouts, text_layout_id):
    for layout in text_layouts.values():
        if layout['exclave_textlayout_info']['layout_id'] == text_layout_id:
            return layout
    return None

def BinaryImagesFromExclavesLayout(layout):
    flags = layout['exclave_textlayout_info']['etl_flags']
    sharedCacheIndex = layout['exclave_textlayout_info'].get('sharedcache_index', 0xffffffff)
    layouts = [ [format_uuid(layout['layoutSegment_uuid']), layout['layoutSegment_loadAddress'], 'P'] for layout in textlayout['exclave_textlayout_segments'] ]
    # 0x4 == kExclaveTextLayoutHasSharedCache
    if ((flags & 0x4) != 0 and sharedCacheIndex < length(layouts)):
        layouts[sharedCacheIndex][2] = "S"
    layouts.sort(key=itemgetter(1))
    return layouts

def GetExclaveLibs(text_layouts, text_layout_id):
    from operator import itemgetter
    textlayout = text_layouts.get(str(text_layout_id))

    # This fallback is needed to preserve compatibility with kcdata generated before rdar://123838752
    # FindTextLayout function should be removed in future
    if not textlayout or textlayout['exclave_textlayout_info']['layout_id'] != text_layout_id:
        textlayout = FindTextLayout(text_layouts, text_layout_id) 

    return BinaryImagesFromExclavesLayout(layout)
    

# kcdata is json at path 'kcdata_stackshot/threads_exclave/0'
def GetEASFrames(AllImageCatalog, kcdata, ipc_entry, notes, scid):
    info = ipc_entry['exclave_ipcstackentry_info']
    asid = info['eise_asid']

    address_spaces = kcdata.get('exclave_addressspace')
    if not address_spaces:
        notes.warn("PID ${PID} TID ${TID} SCID %d Missing address spaces info" % scid)
        return []
    as_info = address_spaces.get(str(asid))
    if not as_info:
        notes.warn("PID ${PID} TID ${TID} SCID %d Missing address space info for ASID 0x%x" % (scid, asid))
        return []
    text_layout_id = as_info['exclave_addressspace_info']['eas_layoutid']
    addr_space_name = as_info['exclave_addressspace_name']
    
    exclave_libs = GetExclaveLibs(kcdata['exclave_textlayout'], text_layout_id)
    
    frames = []
    stack = ipc_entry.get('secure_ecstack_entry', [])
    for stack_item in stack:
        lr = GetLongForAddress(stack_item['lr'])
        # this is a buggy value of unknown origin
        # rdar://123508690 (Some Exclave Stackshot frames ends with invalid value 0xFFFF000000000000)
        if lr == 0xFFFF000000000000:
            continue
        frames.append(GetSymbolInfoForFrame(AllImageCatalog, exclave_libs, lr))

    if frames:
        frame_info = "frames %d to %d" % (notes.offset, notes.offset + len(frames) - 1)
    else:
        frame_info = "no frames"
    notes.info("PID ${PID} TID ${TID} SCID %d ASID 0x%x has address space name '%s' (%s)" % (scid, asid, addr_space_name, frame_info))
    notes.addToOffset(len(frames))
    return frames
    

def GetExclavesFrames(AllImageCatalog, json, scid, notes):
    kcdata = json['kcdata_stackshot']
    threads_exclave = kcdata.get('threads_exclave')
    if not threads_exclave:
        notes.warn("PID ${PID} TID ${TID} no threads_exclave info found, skipping exclaves frames")
        return []

    exclaves_content = threads_exclave.get('0')
    if not exclaves_content:
        notes.warn("PID ${PID} TID ${TID} threads_exclave data not found, skipping exclaves frames")
        return []

    threads_info = exclaves_content.get('thread_exclave')
    if not threads_info:
        notes.warn("PID ${PID} TID ${TID} no thread_exclave info found, skipping exclaves frames")
        return []

    scid_info = threads_info.get(str(scid))
    if not scid_info:
        notes.warn("PID ${PID} TID ${TID} no exclaves info available for SCID %d, skipping exclaves frames" % scid)
        return []

    frames = []

    ipc_stack = scid_info.get("exclave_ipcstackentry")
    if not ipc_stack:
        notes.info("\nPID ${PID} TID ${TID} SCID %d IPC chain is missing" % scid)
        return []
    notes.info("\nPID ${PID} TID ${TID} SCID %d has IPC chain with %d items:" % (scid, len(ipc_stack)))
    for i in reversed(range(len(ipc_stack))):
        ipc_entry = ipc_stack[str(i)]
        entry_frames = GetEASFrames(AllImageCatalog, exclaves_content, ipc_entry, notes, scid)
        frames.extend(entry_frames)

    return frames
    

def InsertExclavesFrames(AllImageCatalog, json, thdata, notes, kernel_frames):
    thread_info = thdata.get('exclaves_thread_info')
    if not thread_info:
        # this is not exclave thread
        return

    scid = thread_info["tei_scid"]
    offset = thread_info["tei_thread_offset"]
    notes.offset = offset

    exclaves_frames = GetExclavesFrames(AllImageCatalog, json, scid, notes)
    
    # insert exclaves frames to offset
    for i in range(len(exclaves_frames)):
        kernel_frames.insert(offset + i, exclaves_frames[i])

class NotesBuilder:
    
    notes = []
    pid = None
    tis = None
    offset = 0

    def __init__(self, pid, tid):
        self.pid = pid
        self.tid = tid
        self.notes = []
        self.offset = 0 # offset of next IPC stack in kernel stack

    # Replace ${PID} with a PID and ${TID} with TID and add newline
    def format(self, note):
        note = note.replace('${PID}', str(self.pid))
        note = note.replace('${TID}', str(self.tid))
        return note + '\n'
    
    def warn(self, note):
        note = self.format(note)
        sys.stdout.write(note)
        self.notes.append(note)

    def info(self, note):
        note = self.format(note)
        self.notes.append(note)
        
    def isEmpty(self):
        return len(self.notes) == 0

    def text(self):
        return ''.join(self.notes)

    def addToOffset(self, frame_count):
        self.offset += frame_count

def SaveStackshotReport(j, outfile_name, incomplete):
    import time
    from operator import itemgetter, attrgetter
    ss = j.get('kcdata_stackshot')
    if not ss:
        print("No KCDATA_BUFFER_BEGIN_STACKSHOT object found. Skipping writing report.")
        return

    timestamp = ss.get('usecs_since_epoch')
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S +0000",time.gmtime(timestamp // 1000000 if timestamp else None))
    except ValueError as e:
        print("couldn't convert timestamp:", str(e))
        timestamp = None

    os_version = ss.get('osversion', 'Unknown')
    timebase = ss.get('mach_timebase_info', {"denom": 1, "numer": 1})

    sc_note = None
    extra_note = None
    dsc_common = None
    shared_cache_info = ss.get('shared_cache_dyld_load_info')
    if shared_cache_info:
        shared_cache_base_addr = shared_cache_info['imageSlidBaseAddress']
        # If we have a slidFirstMapping and it's >= base_address, use that.
        #
        # Otherwise we're processing a stackshot from before the slidFirstMapping
        # field was introduced and corrected.  On ARM the SlidBaseAddress is the
        # same, but on x86 it's off by 0x20000000.  We use 'X86_64' in the
        # kernel version string plus checking kern_page_size == 4k' as
        # proxy for x86_64, and only adjust SlidBaseAddress if the unslid
        # address is precisely the expected incorrect value.
        #
        is_intel = ('X86_64' in ss.get('osversion', "") and
           ss.get('kernel_page_size', 0) == 4096)
        slidFirstMapping = shared_cache_info.get(SC_SLID_FIRSTMAPPING_KEY, -1);
        if slidFirstMapping >= shared_cache_base_addr:
            shared_cache_base_addr = slidFirstMapping
            sc_note = "base-accurate"

        elif is_intel:
            sc_slide = shared_cache_info['imageLoadAddress']
            if (shared_cache_base_addr - sc_slide) == 0x7fff00000000:
                shared_cache_base_addr += 0x20000000
                sc_note = "base-x86-adjusted"
                extra_note = "Shared cache base adjusted for x86. "
            else:
                sc_note = "base-x86-unknown"

        dsc_common = [format_uuid(shared_cache_info['imageUUID']),
                shared_cache_base_addr, "S" ]
        print("Shared cache UUID found from the binary data is <%s> " % str(dsc_common[0]))

    dsc_layout = ss.get('system_shared_cache_layout')

    dsc_libs = []
    if dsc_layout:
        print("Found in memory system shared cache layout with {} images".format(len(dsc_layout)))
        slide = ss.get('shared_cache_dyld_load_info')['imageLoadAddress']

        for image in dsc_layout:
            dsc_libs.append([format_uuid(image['imageUUID']), image['imageLoadAddress'] + slide, "C"])

    AllImageCatalog = []
    obj = {}
    obj["kernel"] = os_version
    if timestamp is not None:
        obj["date"] = timestamp
    obj["reason"] = "kernel panic stackshot"
    obj["incident"] = "ABCDEFGH-1234-56IJ-789K-0LMNOPQRSTUV"
    obj["crashReporterKey"] = "12ab34cd45aabbccdd6712ab34cd45aabbccdd67"
    obj["bootArgs"] = ss.get('boot_args','')
    obj["frontmostPids"] = [0]
    obj["exception"] = "0xDEADF157"
    obj["processByPid"] = {}
    if sc_note is not None:
        obj["sharedCacheNote"] = sc_note

    if incomplete:
        obj["reason"] = "!!!INCOMPLETE!!! kernel panic stackshot"
        obj["notes"] = "Generated by xnu kcdata.py from incomplete data!   Some information is missing! "
    else:
        obj["notes"] = "Generated by xnu kcdata.py. "

    if extra_note is not None:
        obj["notes"] = obj["notes"] + extra_note

    processByPid = obj["processByPid"]
    ssplist = ss.get('task_snapshots', {})
    ssplist.update(ss.get('transitioning_task_snapshots', {}))
    kern_load_info = []
    if "0" in ssplist:
        kc_uuid = ssplist["0"].get('kernelcache_load_info', None)
        if kc_uuid:
            kernelcache_uuid = [format_uuid(kc_uuid['imageUUID']), kc_uuid['imageLoadAddress'], "U" ]
            kern_load_info.append(kernelcache_uuid)

        kl_infos = ssplist["0"].get("dyld_load_info", [])
        for dlinfo in kl_infos:
            kern_load_info.append([format_uuid(dlinfo['imageUUID']), dlinfo['imageLoadAddress'], "K"])

        kl_infos_text_exec = ssplist["0"].get("dyld_load_info_text_exec", [])
        for dlinfo in kl_infos_text_exec:
            kern_load_info.append([format_uuid(dlinfo['imageUUID']), dlinfo['imageLoadAddress'], "T"])

    for pid,piddata in sorted(ssplist.items()):
        processByPid[str(pid)] = {}
        tsnap = processByPid[str(pid)]
        pr_lib_dsc = dsc_common

        # see if there's an alternate shared cache
        scd = piddata.get('shared_cache_dyld_load_info')
        if scd is not None:
            if 'imageSlidBaseAddress' not in scd:
                print("Specific task shared cache format does not include slid shared cache base address. Skipping writing report.")
                return

            scd_uuid = format_uuid(scd['imageUUID'])
            scd_base_addr = scd['imageSlidBaseAddress']
            pr_lib_dsc = [scd_uuid, scd_base_addr, "S"]

        pr_libs = []
        if len(dsc_libs) == 0 and pr_lib_dsc:
            pr_libs.append(pr_lib_dsc)
        _lib_type = "P"
        if int(pid) == 0:
            _lib_type = "K"
            pr_libs = []
        else:
            for dlinfo in piddata.get('dyld_load_info',[]):
                pr_libs.append([format_uuid(dlinfo['imageUUID']), dlinfo['imageLoadAddress'], _lib_type])

        pr_libs.extend(kern_load_info)
        pr_libs.extend(dsc_libs)

        if 'jit_address_range' in piddata:
            address_range = piddata.get('jit_address_range', {})
            tsnap['jitStartAddress'] = address_range['start_address']
            tsnap['jitEndAddress'] = address_range['end_address']
            pr_libs.append([format_uuid("00000000000000000000000000000000"), tsnap['jitStartAddress'] , "J"])
        pr_libs.sort(key=itemgetter(1))
        ttsnap = piddata.get('transitioning_task_snapshot', None)
        if ttsnap is not None:
            # Transitioning task snapshots have "tts_" prefixes; change them to
            # "ts_".
            ttsnap = { key[1:] : value for key,value in ttsnap.items() }
            # Add a note to let people know
            obj["notes"] = obj["notes"] + "PID {} is a transitioning (exiting) task. ".format(pid)
        tasksnap = piddata.get('task_snapshot', ttsnap);
        if tasksnap is None:
            continue;
        tsnap["pid"] = tasksnap["ts_pid"]
        if 'ts_asid' in piddata:
            tsnap["asid"] = piddata["ts_asid"]

        if 'ts_pagetable' in piddata:
            pagetables = []
            for tte in piddata["ts_pagetable"]:
                pagetables.append(tte)
            tsnap["pageTables"] = pagetables

        # Some fields are missing from transitioning_task snapshots.
        if ttsnap is None:
            tsnap["residentMemoryBytes"] = tasksnap["ts_task_size"]
            tsnap["timesDidThrottle"] = tasksnap["ts_did_throttle"]
            tsnap["systemTimeTask"] = GetSecondsFromMATime(tasksnap["ts_system_time_in_terminated_th"], timebase)
            tsnap["pageIns"] = tasksnap["ts_pageins"]
            tsnap["pageFaults"] = tasksnap["ts_faults"]
            tsnap["userTimeTask"] = GetSecondsFromMATime(tasksnap["ts_user_time_in_terminated_thre"], timebase)
        tsnap["procname"] = tasksnap["ts_p_comm"]
        if ttsnap is None:
            tsnap["copyOnWriteFaults"] = tasksnap["ts_cow_faults"]
            tsnap["timesThrottled"] = tasksnap["ts_was_throttled"]
        tsnap["threadById"] = {}
        threadByID = tsnap["threadById"]
        thlist = piddata.get('thread_snapshots', {})
        for tid,thdata in sorted(thlist.items()):
            threadByID[str(tid)] = {}
            thsnap = threadByID[str(tid)]
            if "thread_snapshot" not in thdata:
                print("Found broken thread state for thread ID: %s." % tid)
                break
            threadsnap = thdata["thread_snapshot"]
            thsnap["userTime"] = GetSecondsFromMATime(threadsnap["ths_user_time"], timebase)
            thsnap["id"] = threadsnap["ths_thread_id"]
            thsnap["basePriority"] = threadsnap["ths_base_priority"]
            thsnap["systemTime"] = GetSecondsFromMATime(threadsnap["ths_sys_time"], timebase)
            thsnap["schedPriority"] = threadsnap["ths_sched_priority"]
            thsnap["state"] = GetStateDescription(threadsnap['ths_state'])
            thsnap["qosEffective"] = threadsnap["ths_eqos"]
            thsnap["qosRequested"] = threadsnap["ths_rqos"]

            if "pth_name" in thdata:
                thsnap["name"] = thdata["pth_name"];

            if threadsnap['ths_continuation']:
                thsnap["continuation"] = GetSymbolInfoForFrame(AllImageCatalog, pr_libs, threadsnap['ths_continuation'])
            if "kernel_stack_frames" in thdata:
                kuserframes = []
                for f in thdata["kernel_stack_frames"]:
                    kuserframes.append(GetSymbolInfoForFrame(AllImageCatalog, pr_libs, f['lr']))
                notesBuilder = NotesBuilder(tsnap['pid'], tid)
                InsertExclavesFrames(AllImageCatalog, j, thdata, notesBuilder, kuserframes)
                if not notesBuilder.isEmpty():
                    obj['notes'] += notesBuilder.text()
                thsnap["kernelFrames"] = kuserframes

            if "user_stack_frames" in thdata:
                uframes = []
                for f in thdata["user_stack_frames"]:
                    uframes.append(GetSymbolInfoForFrame(AllImageCatalog, pr_libs, f['lr']))
                thsnap["userFrames"] = uframes

            if "user_stacktop" in thdata:
                (address,) = struct.unpack("<Q", struct.pack("B"*8, *thdata["user_stacktop"]["stack_contents"]))
                thsnap["userStacktop"] = GetSymbolInfoForFrame(AllImageCatalog, pr_libs, address)

            if threadsnap['ths_wait_event']:
                thsnap["waitEvent"] = GetSymbolInfoForFrame(AllImageCatalog, pr_libs, threadsnap['ths_wait_event'])

        if 'thread_waitinfo' in piddata and 'thread_turnstileinfo' in piddata:
            tsnap['waitInfo'] = formatWaitInfoWithTurnstiles(piddata['thread_waitinfo'], piddata['thread_turnstileinfo'], piddata.get('portlabels', None))
        elif 'thread_waitinfo' in piddata:
            portlabels = ss.get('portlabels', None)
            tsnap['waitInfo'] = [formatWaitInfo(x, False, portlabels) for x in piddata['thread_waitinfo']]
        if 'stackshot_task_codesigning_info' in piddata:
            csinfo = piddata.get('stackshot_task_codesigning_info', {})
            tsnap['csFlags'] = csinfo['csflags']
            tsnap['csTrustLevel'] = csinfo['cs_trust_level']
        if 'suspension_info' in piddata:
            suspinfo = piddata.get('suspension_info', {})
            tsnap['suspension_count'] = suspinfo['tss_count']
            tsnap['suspension_duration_secs'] = GetSecondsFromMATime(suspinfo['tss_duration'], timebase)
            tsnap['suspension_last_start'] = GetSecondsFromMATime(suspinfo['tss_last_start'], timebase)
            tsnap['suspension_last_end'] = GetSecondsFromMATime(suspinfo['tss_last_end'], timebase)

            suspsources = piddata.get('suspension_source', [])
            suspension_sources = []
            for source in filter(lambda x: x['tss_time'] != 0, suspsources):
                suspension_sources.append({
                    'suspension_time': GetSecondsFromMATime(source['tss_time'], timebase),
                    'suspension_tid': source['tss_tid'],
                    'suspension_pid': source['tss_pid'],
                    'suspension_procname': source['tss_procname'],
                })

            tsnap['suspension_sources'] = suspension_sources
            # check if process is currently suspended
            if tsnap['suspension_last_start'] > tsnap['suspension_last_end']:
                obj['notes'] += "\nPID {} ({}) is currently suspended (count: {}, total duration: {:.4f}s, last_start: {:.4f}, last_end: {:.4f}) - recent suspensions are:\n".format(pid, tsnap['procname'], tsnap['suspension_count'], tsnap['suspension_duration_secs'], tsnap['suspension_last_start'], tsnap['suspension_last_end'])
                for source in suspension_sources:
                    obj['notes'] += "From PID {} TID {} ({}) - at {}\n".format(source['suspension_pid'], source['suspension_tid'], source['suspension_procname'], source['suspension_time'])

    obj['binaryImages'] = AllImageCatalog
    if outfile_name == '-':
        fh = sys.stdout
    else:
        fh = open(outfile_name, "w")

    header = {}
    header['bug_type'] = 288
    if timestamp is not None:
        header['timestamp'] = timestamp
    header['os_version'] = os_version
    fh.write(json.dumps(header, sort_keys=True))
    fh.write("\n")

    fh.write(json.dumps(obj, sort_keys=True, indent=2, separators=(',', ': ')))
    fh.close()


@contextlib.contextmanager
def data_from_stream(stream):
    try:
        fmap = mmap.mmap(stream.fileno(), 0, mmap.MAP_SHARED, mmap.PROT_READ)
    except:
        yield stream.buffer.read()
    else:
        try:
            yield fmap
        finally:
            fmap.close()

def iterate_kcdatas(kcdata_file):
    with data_from_stream(kcdata_file) as data:
        iterator = kcdata_item_iterator(data)
        kcdata_buffer = KCObject.FromKCItem(next(iterator))

        if isinstance(kcdata_buffer, KCCompressedBufferObject):
            kcdata_buffer.ReadItems(iterator)
            decompressed = kcdata_buffer.Decompress(data)
            iterator = kcdata_item_iterator(decompressed)
            kcdata_buffer = KCObject.FromKCItem(next(iterator))

        if not isinstance(kcdata_buffer, KCBufferObject):
            # ktrace stackshot chunk
            iterator = kcdata_item_iterator(data[16:])
            kcdata_buffer = KCObject.FromKCItem(next(iterator))

        if not isinstance(kcdata_buffer, KCBufferObject):
            try:
                decoded = base64.b64decode(data)
            except:
                pass
            else:
                iterator = kcdata_item_iterator(decoded)
                kcdata_buffer = KCObject.FromKCItem(next(iterator))
        if not isinstance(kcdata_buffer, KCBufferObject):
            import gzip
            from io import BytesIO
            try:
                decompressed = gzip.GzipFile(fileobj=BytesIO(data[:])).read()
            except:
                pass
            else:
                iterator = kcdata_item_iterator(decompressed)
                kcdata_buffer = KCObject.FromKCItem(next(iterator))

        if not isinstance(kcdata_buffer, KCBufferObject):
            raise Exception("unknown file type")


        kcdata_buffer.ReadItems(iterator)
        yield kcdata_buffer

        for magic in iterator:
            kcdata_buffer = KCObject.FromKCItem(magic)
            if kcdata_buffer.i_type == 0:
                continue
            if not isinstance(kcdata_buffer, KCBufferObject):
                raise Exception("unknown file type")
            kcdata_buffer.ReadItems(iterator)
            yield kcdata_buffer

#
# Values for various flag fields.  Each entry's key is the key seen in the
# processed kcdata, the value is an array of bits, from low (0x1) to high, with
# either a string flag name or None for unused holes.
#
# Only put flags in here which are stable - this is run against stackshots
# of all different versions.  For anything unstable, we'll need a decoder ring
# added to the stackshot.
#
PRETTIFY_FLAGS = {
    'jcs_flags': [
       'kCoalitionTermRequested',
       'kCoalitionTerminated',
       'kCoalitionReaped',
       'kCoalitionPrivileged',
    ],
    'sharedCacheFlags': [
       'kSharedCacheSystemPrimary',
       'kSharedCacheDriverkit'
       'kSharedCacheAOT',
    ],
    'stackshot_in_flags': [ # STACKSHOT_*, also stackshot_out_flags
        'get_dq',
        'save_loadinfo',
        'get_global_mem_stats',
        'save_kext_loadinfo',
        None,
        None,
        None,
        None,
        'active_kernel_threads_only',
        'get_boot_profile',
        'do_compress',
        None,
        None,
        'save_imp_donation_pids',
        'save_in_kernel_buffer',
        'retrieve_existing_buffer',
        'kcdata_format',
        'enable_bt_faulting',
        'collect_delta_snapshot',
        'collect_sharedcache_layout',
        'trylock',
        'enable_uuid_faulting',
        'from_panic',
        'no_io_stats',
        'thread_waitinfo',
        'thread_group',
        'save_jetsam_coalitions',
        'instrs_cycles',
        'asid',
        'page_tables',
        'disable_latency_info',
        'save_dyld_compactinfo',
        'include_driver_threads_in_kernel',
        'exclaves',
    ],
    'system_state_flags': [
        'kUser64_p',
        'kKern64_p',
    ],
    'tgs_flags': [
        'kThreadGroupEfficient',
        'kThreadGroupApplication',
        'kThreadGroupCritical',
        'kThreadGroupBestEffort',
        None,
        None,
        None,
        None,
        'kThreadGroupUIApplication',
        'kThreadGroupManaged',
        'kThreadGroupStrictTimers',
    ],
    'ths_ss_flags': [
        'kUser64_p',
        'kKern64_p',
        'kHasDispatchSerial',
        'kStacksPCOnly',
        'kThreadDarwinBG',
        'kThreadIOPassive',
        'kThreadSuspended',
        'kThreadTruncatedBT',
        'kGlobalForcedIdle',
        'kThreadFaultedBT',
        'kThreadTriedFaultBT',
        'kThreadOnCore',
        'kThreadIdleWorker',
        'kThreadMain',
        'kThreadTruncKernBT',
        'kThreadTruncUserBT',
        'kThreadTruncUserAsyncBT',
        'kThreadExclaveRPCActive',
        'kThreadExclaveUpcallActive',
        'kThreadExclaveSchedulerRequest',
    ],
    'ths_state': [
        'TH_WAIT',
        'TH_SUSP',
        'TH_RUN',
        'TH_UNINT',
        'TH_TERMINATE',
        'TH_TERMINATE2',
        'TH_WAIT_REPORT',
        'TH_IDLE',
    ],
    'ts_ss_flags': [
        'kUser64_p',
        'kKern64_p',
        'kTaskRsrcFlagged',
        'kTerminatedSnapshot',
        'kPidSuspended',
        'kFrozen',
        'kTaskDarwinBG',
        'kTaskExtDarwinBG',
        'kTaskVisVisible',
        'kTaskVisNonvisible',
        'kTaskIsForeground',
        'kTaskIsBoosted',
        'kTaskIsSuppressed',
        'kTaskIsTimerThrottled',
        'kTaskIsImpDonor',
        'kTaskIsLiveImpDonor',
        'kTaskIsDirty',
        'kTaskWqExceededConstrainedThreadLimit',
        'kTaskWqExceededTotalThreadLimit',
        'kTaskWqFlagsAvailable',
        'kTaskUUIDInfoFaultedIn',
        'kTaskUUIDInfoMissing',
        'kTaskUUIDInfoTriedFault',
        'kTaskSharedRegionInfoUnavailable',
        'kTaskTALEngaged',
        None,
        'kTaskIsDirtyTracked',
        'kTaskAllowIdleExit',
        'kTaskIsTranslated',
        'kTaskSharedRegionNone',
        'kTaskSharedRegionSystem',
        'kTaskSharedRegionOther',
        'kTaskDyldCompactInfoNone',
        'kTaskDyldCompactInfoTooBig',
        'kTaskDyldCompactInfoFaultedIn',
        'kTaskDyldCompactInfoMissing',
        'kTaskDyldCompactInfoTriedFault',
        'kTaskWqExceededCooperativeThreadLimit',
        'kTaskWqExceededActiveConstrainedThreadLimit',
    ],
    'turnstile_flags': [
        'turnstile_status_unknown',
        'turnstile_status_locked_waitq',
        'turnstile_status_workqueue',
        'turnstile_status_thread',
        'turnstile_status_blocked_on_task',
        'turnstile_status_held_iplock',
    ],
    'portlabel_flags': [
        'label_read_failed',
        'service_throttled',
    ],
    'esc_flags': [
        'kExclaveScresultHaveIPCStack',
    ],
    'eise_flags': [
        'kExclaveIpcStackEntryHaveInvocationID',
        'kExclaveIpcStackEntryHaveStack',
    ],
    'eas_flags': [
        'kExclaveAddressSpaceHaveSlide',
    ],
    'etl_flags': [
        'kExclaveTextLayoutLoadAddressesSynthetic',
        'kExclaveTextLayoutLoadAddressesUnslid',
        'kExclaveTextLayoutHasSharedCache',
    ],
}
PRETTIFY_FLAGS['stackshot_out_flags'] = PRETTIFY_FLAGS['stackshot_in_flags']
PRETTIFY_FLAGS['tts_ss_flags'] = PRETTIFY_FLAGS['ts_ss_flags']

# Fields which should never be hexified
PRETTIFY_DONTHEX = {
    'stackshot_in_pid': True,
    'tts_pid': True,
    'ts_pid': True,
    'donating_pids': True,
    'ppid': True,
}

# Only hex() the value if it is multiple digits
def prettify_hex(v):
    if v < -9 or v > 9:
        return hex(v)
    return str(v)

def prettify_flags(v, flags):
    output=""
    seen = 0
    if v == 0:
        return "0"
    for (s, n) in zip(range(len(flags)),flags):
        if n is None:
            continue
        if (v & (2 ** s)):
            output += "|" + n
            seen |= 2 ** s
    if output == "":
        return prettify_hex(v)
    rest = (v & ~seen)
    if (rest != 0):
        output += "|" + prettify_hex(rest)
    return prettify_hex(v) + " (" + output[1:] + ")"

def prettify_core(data, mosthex, key, portlabels):
    if key == 'stack_contents':
        (address,) = struct.unpack("<Q", struct.pack("B"*8, *data))
        return '0x%X' % address

    elif isinstance(data, list):
        if 'uuid' in key.lower() and len(data) == 16:
            return '%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X' % tuple(data)

        return [prettify_core(x, mosthex, key, portlabels) for x in data]

    elif key == 'thread_waitinfo':
        return formatWaitInfo(data, mosthex, portlabels)

    elif isinstance(data, dict):
        if 'portlabels' in data:
            portlabels = data['portlabels']
        newdata = dict()
        for key, value in data.items():
            if mosthex and key != 'task_snapshots' and len(key) > 0 and key.isnumeric():
                key = prettify_hex(int(key))
            newdata[key] = prettify_core(value, mosthex, key, portlabels)
        return newdata

    elif 'address' in key.lower() and isinstance(data, (int, long)):
        return '0x%X' % data
    elif key == 'lr' or key == SC_SLID_FIRSTMAPPING_KEY:
        return '0x%X' % data
    elif key in PRETTIFY_FLAGS and isinstance(data, (int, long)):
        return prettify_flags(data, PRETTIFY_FLAGS[key])
    elif key.endswith('_flags') and isinstance(data, (int, long)):
        return prettify_hex(data)

    elif mosthex and not PRETTIFY_DONTHEX.get(key, False):
        if isinstance(data, (int, long)):
            return prettify_hex(data)
        elif isinstance(data, str) and len(data) > 0 and data.isnumeric():
            return prettify_hex(int(data))
        return data

    else:
        return data

def prettify(data, mosthex):
    return prettify_core(data, mosthex, "", None)

# N.B.: This is called directly from `xnu.py` for `panicdata -S XXX.ips`'s implementation.
def decode_kcdata_file(kcdata_file, stackshot_file, multiple=False, prettyhex=False, pretty=False, output_as_plist=False):
    for i,kcdata_buffer in enumerate(iterate_kcdatas(kcdata_file)):
        if i > 0 and not multiple:
            break

        str_data = "{" + kcdata_buffer.GetJsonRepr() + "}"
        str_data = str_data.replace("\t", "    ")

        try:
            json_obj = json.loads(str_data)
        except:
            print("JSON reparsing failed!  Printing string data!\n", file=sys.stderr)
            import textwrap
            print(textwrap.fill(str_data, 100))
            raise

        if prettyhex:
            json_obj = prettify(json_obj, True)
        elif pretty:
            json_obj = prettify(json_obj, False)

        if stackshot_file:
            SaveStackshotReport(json_obj, stackshot_file, G.data_was_incomplete)
        elif output_as_plist:
            import Foundation
            plist = Foundation.NSPropertyListSerialization.dataWithPropertyList_format_options_error_(
                json_obj, Foundation.NSPropertyListXMLFormat_v1_0, 0, None)[0].bytes().tobytes()
            #sigh.  on some pythons long integers are getting output with L's in the plist.
            plist = re.sub(r'^(\s*<integer>\d+)L(</integer>\s*)$', r"\1\2", BytesToString(plist), flags=re.MULTILINE)
            print(plist,)
        else:
            print(json.dumps(json_obj, sort_keys=True, indent=4, separators=(',', ': ')))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Decode a kcdata binary file.")
    parser.add_argument("-l", "--listtypes", action="store_true", required=False, default=False,
                        help="List all known types",
                        dest="list_known_types")

    parser.add_argument("-s", "--stackshot", required=False, default=False,
                        help="Generate a stackshot report file",
                        dest="stackshot_file")

    parser.add_argument("--multiple", help="look for multiple stackshots in a single file", action='store_true')

    parser.add_argument("-p", "--plist", required=False, default=False,
                        help="output as plist", action="store_true")

    parser.add_argument("-S", "--sdk", required=False, default="", help="sdk property passed to xcrun command to find the required tools. Default is empty string.", dest="sdk")
    parser.add_argument("-P", "--pretty", default=False, action='store_true', help="make the output a little more human readable")
    parser.add_argument("-X", "--prettyhex", default=False, action='store_true', help="make the output a little more human readable, and print most things as hex")
    parser.add_argument("--incomplete", action='store_true', help="accept incomplete data")
    parser.add_argument("kcdata_file", type=argparse.FileType('r'), help="Path to a kcdata binary file.")

    class VerboseAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            logging.basicConfig(level=logging.INFO, stream=sys.stderr, format='%(message)s')
    parser.add_argument('-v', "--verbose", action=VerboseAction, nargs=0)

    args = parser.parse_args()

    if args.multiple and args.stackshot_file:
        raise NotImplementedError

    if args.pretty and args.stackshot_file:
        raise NotImplementedError

    if args.list_known_types:
        for (n, t) in KNOWN_TYPES_COLLECTION.items():
            print("%d : %s " % (n, str(t)))
        sys.exit(1)

    if args.incomplete or args.stackshot_file:
        G.accept_incomplete_data = True

    decode_kcdata_file(args.kcdata_file, args.stackshot_file, args.multiple, args.prettyhex, args.pretty, args.plist)
