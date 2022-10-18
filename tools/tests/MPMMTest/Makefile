include ../Makefile.common

SYMROOT?=$(shell /bin/pwd)

CFLAGS := -g -O2 -isysroot $(SDKROOT) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
CFLAGS += -Wno-deprecated-declarations

# $(ARCH_CONFIGS) is set by Makefile.common

DSTROOT?=$(shell /bin/pwd)

ARCH_64_TARGETS := MPMMtest_64 KQMPMMtest_64 KQMPMMtest_64D
TARGETS := MPMMtest_perf.sh $(if $(ARCH_CONFIGS_64), $(ARCH_64_TARGETS))

all:	$(addprefix $(DSTROOT)/, $(TARGETS))

$(DSTROOT)/MPMMtest_64: MPMMtest.c
	${CC} ${CFLAGS} ${ARCH_FLAGS_64} -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/KQMPMMtest_64: KQMPMMtest.c
	${CC} ${CFLAGS} ${ARCH_FLAGS_64} -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/KQMPMMtest_64D: KQMPMMtest.c
	${CC} ${CFLAGS} ${ARCH_FLAGS_64} -DDIRECT_MSG_RCV=1 -o $(SYMROOT)/$(notdir $@) $?
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

$(DSTROOT)/MPMMtest_perf.sh: MPMMtest_run.sh
	cp $? $@
	chmod +x $@

clean:
	rm -rf $(addprefix $(DSTROOT)/,$(TARGETS)) $(addprefix $(SYMROOT)/,$(TARGETS)) $(SYMROOT)/*.dSYM
