include ../Makefile.common

OBJROOT?=$(shell /bin/pwd)

DSTROOT?=$(shell /bin/pwd)

CFLAGS:=$(ARCH_FLAGS) -g -Wall -Os -isysroot $(SDKROOT) -framework CoreFoundation
CFLAGS += -Wl,-sectcreate,__INFO_FILTER,__disable,/dev/null

all: $(DSTROOT)/mktimer_test

$(DSTROOT)/mktimer_test: $(OBJROOT)/mktimer_test.c
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -rf $(DSTROOT)/mktimer_test $(DSTROOT)/mk_timer_test.dSYM
