export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

# in6.h is covered by ../netinet/netinet.modulemap.
DATAFILES = \
	ah.h ipsec.h \
	esp.h in6.h ipcomp.h raw_ip6.h \
	scope6_var.h in6_var.h nd6.h

MODULEMAPFILES = \
	netinet6.modulemap

PRIVATE_DATAFILES = \
	in6.h \
	in6_private.h \
	in6_pcb.h \
	in6_var.h \
	ip6_var.h \
	mld6_var.h \
	nd6.h \
	scope6_var.h

DRIVERKIT_DATAFILES = \
	in6.h

PRIVATE_KERNELFILES = \
	ah6.h esp6.h esp_rijndael.h esp_chachapoly.h \
	in6_gif.h in6_ifattach.h ip6_ecn.h ip6protosw.h \
	ipsec6.h tcp6_var.h udp6_var.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MODULEMAP_MI_LIST = ${MODULEMAPFILES}

INSTALL_DRIVERKIT_MI_LIST = ${DRIVERKIT_DATAFILES}

INSTALL_MI_DIR = netinet6

# in6_private.h is covered by ../netinet/netinet_private.modulemap.
INSTALL_MI_LCL_LIST = in6_private.h

EXPORT_MI_LIST = ${DATAFILES} ${INSTALL_MI_LCL_LIST}

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_SF_MI_LCL_LIST = $(sort ${DATAFILES} ${PRIVATE_DATAFILES})

INSTALL_KF_MI_LCL_LIST = $(sort ${DATAFILES} ${PRIVATE_DATAFILES} ${PRIVATE_KERNELFILES})

include $(MakeInc_rule)
include $(MakeInc_dir)
