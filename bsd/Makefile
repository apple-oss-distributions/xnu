export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

SETUP_SUBDIRS = sys

INSTINC_SUBDIRS = \
	bsm \
	crypto \
	dev \
	libkern \
	machine \
	miscfs \
	net \
	netinet \
	netinet6 \
	netkey \
	nfs \
	security \
	skywalk \
	pthread \
	sys \
	uuid \
	vfs

INSTINC_SUBDIRS_X86_64 = \
	i386 \
	crypto

INSTINC_SUBDIRS_X86_64H = \
	i386 \
	crypto

INSTINC_SUBDIRS_ARM64 = \
	arm

EXPINC_SUBDIRS = \
	bsm \
	crypto/entropy \
	dev \
	libkern \
	machine \
	miscfs \
	net \
	netinet \
	netinet6 \
	netkey \
	security \
	skywalk \
	pthread \
	sys \
	uuid \
	vfs \
	vm

EXPINC_SUBDIRS_X86_64 = \
	i386

EXPINC_SUBDIRS_X86_64H = \
	i386

EXPINC_SUBDIRS_ARM64 = \
	arm

COMP_SUBDIRS =	\
	conf

INSTTEXTFILES_SUBDIRS =	\
	dev \
	man \
	sys

INSTTEXTFILES_SUBDIRS_X86_64 = \
	dev

INSTTEXTFILES_SUBDIRS_X86_64H = \
	dev

INSTTEXTFILES_SUBDIRS_ARM64 = \
	dev

include $(MakeInc_rule)
include $(MakeInc_dir)
