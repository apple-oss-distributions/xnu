export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
    machine \
    c++ \
    crypto \
    img4 \
    image4 \
    coretrust \
    apple_encrypted_archive \
    amfi \
    coreanalytics \
    compression 

INSTINC_SUBDIRS_X86_64 = \
        i386
INSTINC_SUBDIRS_X86_64H = \
        i386
INSTINC_SUBDIRS_ARM64 = \
        arm

EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}
EXPINC_SUBDIRS_X86_64 = ${INSTINC_SUBDIRS_X86_64}
EXPINC_SUBDIRS_X86_64H = ${INSTINC_SUBDIRS_X86_64H}
EXPINC_SUBDIRS_ARM64 = ${INSTINC_SUBDIRS_ARM64}

# Files that are public on macOS, but private on embedded
EMBEDDED_PRIVATE_DATAFILES = \
	OSDebug.h \
	OSKextLib.h

ifeq ($(filter $(SUPPORTED_EMBEDDED_PLATFORMS) $(SUPPORTED_SIMULATOR_PLATFORMS),$(PLATFORM)),)
EXTRA_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
else
EXTRA_PRIVATE_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
endif

# These are covered by CoreOSModuleMaps because they're mixed in with headers
# from other projects in libkern/.
DATAFILES = $(sort \
	OSByteOrder.h \
	_OSByteOrder.h \
	OSReturn.h \
	OSTypes.h \
	$(EXTRA_DATAFILES))

DRIVERKIT_DATAFILES = \
	OSByteOrder.h \
	_OSByteOrder.h

KERNELFILES = $(sort \
	${DATAFILES} \
	OSAtomic.h \
	OSBase.h \
	OSMalloc.h \
	locks.h	\
	sysctl.h \
	tree.h \
	zconf.h	\
	zlib.h \
	crc.h \
	Block.h \
	$(EXTRA_PRIVATE_DATAFILES))

PRIVATE_KERNELFILES = \
	OSKextLibPrivate.h \
	OSSerializeBinary.h \
	kernel_mach_header.h \
	kext_request_keys.h \
	mkext.h \
	prelink.h \
	section_keywords.h \
	Block_private.h \
	ptrauth_utils.h

PRIVATE_DATAFILES = $(sort \
	${PRIVATE_KERNELFILES} \
	tree.h \
	$(EXTRA_PRIVATE_DATAFILES))

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_LCL_LIST = $(sort OSKextLibPrivate.h ${EXTRA_PRIVATE_DATAFILES})

INSTALL_DRIVERKIT_MI_LIST = ${DRIVERKIT_DATAFILES}

DRIVERKITINCDIR = $(DRIVERKITSDKHEADERSROOT)/usr/local/include

INSTALL_MI_DIR = libkern

INSTALL_SF_MI_LCL_LIST =        \
	${DATAFILES} \
	${PRIVATE_DATAFILES} \
	kext_panic_report.h  \
	OSCrossEndian.h

INSTALL_KF_MI_LIST = ${KERNELFILES}

INSTALL_KF_MI_LCL_LIST = ${KERNELFILES} ${PRIVATE_KERNELFILES}

EXPORT_MI_LIST = \
	$(sort ${KERNELFILES} ${PRIVATE_DATAFILES}) \
	kxld.h                 \
	kxld_types.h           \
	stack_protector.h

EXPORT_MI_GEN_LIST = version.h

EXPORT_MI_DIR = libkern

version.h: version.h.template $(NEWVERS) $(XNU_VERSION)
	@$(LOG_GENERATE) "libkern/$@$(Color0) from $(ColorF)$<"
	$(_v)install $(DATA_INSTALL_FLAGS) $< $@
	$(_v)$(NEWVERS) $@ > /dev/null

include $(MakeInc_rule)
include $(MakeInc_dir)
