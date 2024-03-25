from xnu import *
from utils import *
import ctypes

MBSHIFT = 20
MSIZE = 256
MCLBYTES = 2048
MBIGCLBYTES = 4096
M16KCLBYTES = 16384

MB_INUSE = 1
MB_COMP_INUSE = 2 
MB_SCVALID = 4

SLF_MAPPED = 0x0001
SLF_PARTIAL = 0x0002
SLF_DETACHED = 0x0004

INTP = ctypes.POINTER(ctypes.c_int)

MCF_NOCPUCACHE = 0x10

def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.items())
    enums['reverse_mapping'] = reverse
    return type('Enum', (), enums)

Mbuf_Type = enum(
    'MT_FREE',
    'MT_DATA',
    'MT_HEADER',
    'MT_SOCKET',
    'MT_PCB',
    'MT_RTABLE',
    'MT_HTABLE',
    'MT_ATABLE',
    'MT_SONAME',
    'MT_SOOPTS',
    'MT_FTABLE',
    'MT_RIGHTS',
    'MT_IFADDR',
    'MT_CONTROL',
    'MT_OOBDATA',
    'MT_TAG',
    'MT_LAST')

M_EXT           = 0x0001
M_PKTHDR        = 0x0002
M_EOR           = 0x0004
M_PROTO1        = 0x0008
M_PROTO2        = 0x0010
M_PROTO3        = 0x0020
M_LOOP          = 0x0040
M_PROTO5        = 0x0080

M_BCAST         = 0x0100
M_MCAST         = 0x0200
M_FRAG          = 0x0400
M_FIRSTFRAG     = 0x0800
M_LASTFRAG      = 0x1000
M_PROMISC       = 0x2000
M_HASFCS        = 0x4000
M_TAGHDR        = 0x8000

mbuf_flags_strings = [
    "EXT",
    "PKTHDR",
    "EOR",
    "PROTO1",
    "PROTO2",
    "PROTO3",
    "LOOP",
    "PROTO5",

    "BCAST",
    "MCAST",
    "FRAG",
    "FIRSTFRAG",
    "LASTFRAG",
    "PROMISC",
    "HASFCS",
    "TAGHDR"]

mbuf_pkt_crumb_strings = [
    "TS_COMP_REQ",
    "TS_COMP_CB",
    "DLIL_OUTPUT",
    "FLOW_TX",
    "FQ_ENQUEUE",
    "FQ_DEQUEUE",
    "SK_PKT_COPY",
    "TCP_OUTPUT",
    "UDP_OUTPUT",
    "SOSEND",
    "DLIL_INPUT",
    "IP_INPUT",
    "TCP_INPUT",
    "UDP_INPUT"]
