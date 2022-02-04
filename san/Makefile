export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

SETUP_SUBDIRS = \
	memory \
	coverage

EXPINC_SUBDIRS = \
	memory \
	coverage

INSTINC_SUBDIRS = \
	memory \
	coverage

COMP_SUBDIRS = \
	conf

CONFIG_SUBDIRS = \
	memory \
	coverage

include $(MakeInc_rule)
include $(MakeInc_dir)
