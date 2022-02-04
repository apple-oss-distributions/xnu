CXXFLAGS=-Wall -std=c++20 -Os -arch x86_64 -arch arm64

TARGETS	= kt-dump

all:	$(TARGETS)

kt-dump: kt-dump.cpp
	${CXX} ${CXXFLAGS} -o $@ $?
clean:
	rm -rf $(TARGETS)
