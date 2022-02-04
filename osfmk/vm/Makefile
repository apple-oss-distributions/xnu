export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES =

PRIVATE_DATAFILES =

KERNELFILES = \
	memory_types.h \
	pmap.h \
	lz4.h \
	lz4_constants.h \
	lz4_assembly_select.h \
	vm_fault.h \
	vm_kern.h \
	vm_map.h \
	vm_options.h \
	vm_pageout.h \
	vm_protos.h \
	vm_shared_region.h \
	vm_compressor_algorithms.h \
	WKdm_new.h

PRIVATE_KERNELFILES = \
	pmap_cs.h

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
EXPORT_MI_LIST = ${KERNELFILES} ${PRIVATE_KERNELFILES}

EXPORT_MI_DIR = vm

include $(MakeInc_rule)
include $(MakeInc_dir)
