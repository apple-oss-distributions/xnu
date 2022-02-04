include ../Makefile.common

DSTROOT?=$(shell /bin/pwd)

all: $(DSTROOT)/kernpost_test_report

$(DSTROOT)/kernpost_test_report: kernpost_test_report.lua
	cp $^ $@
	chmod +x $@

clean:
	rm -f $(DSTROOT)/kernpost_test_report