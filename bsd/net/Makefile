export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	altq classq pktsched

# Additional private file for macOS
ifeq ($(PLATFORM),MacOSX)
MACOS_PRIVATE_DATAFILES = \
	remote_vif.h
endif

# Files that are public on macOS, but private on embedded
EMBEDDED_PRIVATE_DATAFILES = \
	if_media.h \
	if_mib.h \
	route.h

ifeq ($(filter $(SUPPORTED_EMBEDDED_PLATFORMS) $(SUPPORTED_SIMULATOR_PLATFORMS),$(PLATFORM)),)
EXTRA_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
else
EXTRA_PRIVATE_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
endif

DATAFILES= $(sort \
	bpf.h \
	dlil.h \
	ethernet.h \
	if.h \
	if_arp.h \
	if_dl.h \
	if_llc.h \
	if_types.h \
	if_var.h \
	if_var_status.h \
	if_utun.h \
	kext_net.h \
	ndrv.h \
	pfkeyv2.h	\
	net_kev.h \
	$(EXTRA_DATAFILES))

MODULEMAPFILES = \
	net.modulemap

KERNELFILES= \
	kpi_interface.h kpi_interfacefilter.h kpi_protocol.h \
	if_ether.h init.h radix.h

PRIVATE_DATAFILES = $(sort \
	bpf.h \
	content_filter.h \
	etherdefs.h \
	firewire.h \
	if.h \
	if_private.h \
	if_bond_var.h \
	if_bond_internal.h \
	if_bridgevar.h \
	if_ipsec.h \
	if_llreach.h \
	if_media.h \
	if_mib_private.h \
	if_pflog.h \
	if_ports_used.h \
	if_ppp.h \
	if_utun.h \
	if_var.h \
	if_var_private.h \
	if_vlan_var.h \
	if_fake_var.h \
	if_redirect.h \
	iptap.h \
	lacp.h \
	kctl_test.h \
	multi_layer_pkt_log.h \
	ndrv_var.h \
	necp.h \
	net_api_stats.h \
	net_log_common.h \
	netsrc.h \
	network_agent.h \
	ntstat.h \
	packet_mangler.h \
	pfkeyv2.h \
	pfvar.h \
	pktap.h \
	droptap.h \
	ppp_defs.h \
	radix.h \
	raw_cb.h \
	route_private.h \
	net_perf.h \
	net_kev.h \
	nat464_utils.h \
	$(MACOS_PRIVATE_DATAFILES) \
	$(EXTRA_PRIVATE_DATAFILES))

PRIVATE_MODULEMAPFILES = \
	net_private.modulemap

DRIVERKIT_DATAFILES = \
	bpf.h \
	if.h \
	if_var.h \
	if_var_status.h \
	if_media.h \
	ethernet.h

PRIVATE_KERNELFILES = $(filter-out radix.h,${KERNELFILES}) \
	bpfdesc.h ppp_comp.h \
	zlib.h bpf_compat.h net_osdep.h \
	flowadv.h net_perf.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MODULEMAP_MI_LIST = ${MODULEMAPFILES}

INSTALL_DRIVERKIT_MI_LIST = ${DRIVERKIT_DATAFILES}

INSTALL_MI_DIR = net

INSTALL_MI_LCL_LIST = $(sort if_ipsec.h if_mib_private.h if_private.h if_var_private.h \
	if_vlan_var.h necp.h network_agent.h route_private.h ${EXTRA_PRIVATE_DATAFILES})

INSTALL_MODULEMAP_MI_LCL_LIST = ${PRIVATE_MODULEMAPFILES}

EXPORT_MI_LIST	= ${INSTALL_MI_LIST} ${INSTALL_MI_LCL_LIST} ${KERNELFILES}

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

INSTALL_SF_MI_LCL_LIST = $(sort ${DATAFILES} ${PRIVATE_DATAFILES})

INSTALL_KF_MI_LCL_LIST = $(sort ${DATAFILES} ${PRIVATE_DATAFILES} ${PRIVATE_KERNELFILES})

include $(MakeInc_rule)
include $(MakeInc_dir)
