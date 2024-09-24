#
# Copyright (C) 2023 Apple Inc. All rights reserved.
#

# the xnu build system will only ever call us with the default target
.DEFAULT_GOAL := install

DSTSUBPATH := $(DSTROOT)/AppleInternal/CoreOS/tests/lldbmacros

#
# Installs full source tree because tests depend on dSYM sources.
# It is not required to pull them from dSYM because contents are
# identical.
#

EXCLUDES := --exclude=Makefile



install:
	mkdir -p $(DSTSUBPATH)
	rsync -rlpt $(EXCLUDES) $(SRCROOT)/* $(DSTSUBPATH)/
