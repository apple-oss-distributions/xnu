export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES =

PRIVATE_DATAFILES = \
	vm_compressor_info.h

KERNELFILES = \
	memory_types.h \
	pmap.h \
	lz4.h \
	lz4_constants.h \
	lz4_assembly_select.h \
	vm_fault.h \
	vm_kern.h \
	vm_map.h \
	vm_memtag.h \
	vm_options.h \
	vm_pageout.h \
	vm_protos.h \
	vm_far.h \
	vm_shared_region.h \
	vm_dyld_pager.h \
	vm_compressor_algorithms.h \
	WKdm_new.h

PRIVATE_KERNELFILES = \
	pmap_cs.h

XNU_ONLY_EXPORTS = \
	memory_object_xnu.h \
	vm_compressor_algorithms_xnu.h \
	vm_compressor_backing_store_xnu.h \
	vm_compressor_xnu.h \
	vm_fault_xnu.h \
	vm_kern_xnu.h \
	vm_map_xnu.h \
	vm_memory_entry.h \
	vm_memory_entry_xnu.h \
	vm_object_xnu.h \
	vm_page.h \
	vm_pageout_xnu.h \
	vm_purgeable_xnu.h \
	vm_reclaim_xnu.h \
	vm_shared_region_xnu.h


# Internal headers for the sake of bsd/vm/* and bsd/kern/kern_mman.c files only
XNU_ONLY_EXPORTS += \
	vm_compressor_backing_store_internal.h \
	vm_dyld_pager_internal.h \
	vm_map_internal.h \
	vm_protos_internal.h \
	vm_sanitize_internal.h \
	vm_sanitize_telemetry.h \
	vm_shared_region_internal.h

# Internal files exported with specific subsystems
# who needs access to some VM internals.
#
# These headers must be included from C/C++ translation units,
# never from other headers, and only by the named subsystems.
XNU_ONLY_EXPORTS += \
	vm_iokit.h \
	vm_ubc.h \
	vm_upl.h

# /usr/include
INSTALL_MI_LIST = ${DATAFILES}

# /System/Library/Frameworks/System.framework/PrivateHeaders
INSTALL_SF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

# /System/Library/Frameworks/Kernel.framework/Headers
INSTALL_KF_MI_LIST = ${KERNELFILES}

# /System/Library/Frameworks/Kernel.framework/PrivateHeaders
INSTALL_KF_MI_LCL_LIST = ${KERNELFILES} ${PRIVATE_KERNELFILES}

INSTALL_MI_DIR = vm

# Exported to rest of XNU for compilation
EXPORT_MI_LIST = ${KERNELFILES} ${PRIVATE_KERNELFILES} ${XNU_ONLY_EXPORTS} ${PRIVATE_DATAFILES}

EXPORT_MI_DIR = vm

include $(MakeInc_rule)
include $(MakeInc_dir)
