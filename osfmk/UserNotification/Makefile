export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

MIG_TYPES = \
	UNDTypes.defs

MIG_DEFS = \
	UNDRequest.defs \
	UNDReply.defs

PRIVATE_DATAFILES = \
	UNDTypes.h \
	${MIG_TYPES} \
	${MIG_DEFS}

KERNELFILES = \
	KUNCUserNotifications.h \
	${PRIVATE_DATAFILES}

INSTALL_MI_LIST =
INSTALL_SF_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_MI_GEN_LIST =

INSTALL_MI_DIR = UserNotification

EXPORT_MI_LIST = ${KERNELFILES}

EXPORT_MI_GEN_LIST =

EXPORT_MI_DIR = UserNotification

#
# Build path
#
INCFLAGS_MAKEFILE= -I..

MIG_KUHDRS = \
	UNDRequest.h

MIG_KUSRC = \
	UNDRequest.c

MIG_KSHDRS = \
	UNDReplyServer.h

MIG_KSSRC = \
	UNDReplyServer.c

COMP_FILES = ${MIG_KUSRC} ${MIG_KSSRC}

do_build_all:: $(COMP_FILES)

${COMP_FILES} : ${MIG_TYPES}

${MIG_KUSRC} : \
	%.c : %.defs
	@$(LOG_MIG) "$@"
	$(_v)${MIG} ${MIGFLAGS} ${MIGKUFLAGS}        \
		-user    $*.c              \
		-header  $*.h              \
		-server  /dev/null		\
		-sheader /dev/null		\
		$<

${MIG_KSSRC}: \
	%Server.c : %.defs
	@$(LOG_MIG) "$@"
	$(_v)${MIG} ${MIGFLAGS} ${MIGKSFLAGS}        \
		-user    /dev/null              \
		-header  /dev/null              \
		-server  $*Server.c		\
		-sheader $*Server.h		\
		$<

include $(MakeInc_rule)
include $(MakeInc_dir)
