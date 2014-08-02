SHELL=/bin/sh
OS := $(shell uname -s)
#####
LIBPCAP=-lpcap

## If you are not installing the pfring-aware libpcap uncomment:
#PFRINGDIR=../../../PF_RING
#LIBPFRING=${PFRINGDIR}/userland/lib/libpfring.a -lnuma -lrt
#PCAPDIR=${PFRINGDIR}/userland/libpcap-1.1.1-ring
#LIBPCAP=${PCAPDIR}/libpcap.a

ifeq ($(OS),Linux)
LIBPCAP += -lrt
endif

JSON_HOME=third-party/json-c
JSON_INC=-I$(JSON_HOME)
JSON_LIB=$(JSON_HOME)/.libs/libjson-c.a

INC=-I../src/include/ $(JSON_INC)
LIB=../src/lib/.libs/libndpi.a ${LIBPCAP} ${LIBPFRING} $(JSON_LIB) -lpthread
FLAGS=-O2 #-g #-fno-color-diagnostics

ndpiReader: ndpiReader.c Makefile ../src/lib/.libs/libndpi.a $(JSON_LIB)
	gcc $(FLAGS) $(INC) ndpiReader.c -o ndpiReader $(LIB)


$(JSON_LIB):
	cd $(JSON_HOME); ./autogen.sh; ./configure; make

clean:
	\/bin/rm -f ndpiReader
