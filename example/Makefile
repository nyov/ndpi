#PFRINGDIR=../../../PF_RING
#LIBPFRING=${PFRINGDIR}/userland/lib/libpfring.a -lnuma -lrt
#PCAPDIR=${PFRINGDIR}/userland/libpcap-1.1.1-ring
#LIBPCAP=${PCAPDIR}/libpcap.a

LIBPCAP=-lpcap -lrt

INC=-I../src/include/
LIB=../src/lib/.libs/libndpi.a ${LIBPCAP} ${LIBPFRING} -lpthread
FLAGS=-O2 #-g #-fno-color-diagnostics
ndpiReader: ndpiReader.c Makefile ../src/lib/.libs/libndpi.a
	gcc $(FLAGS) $(INC) ndpiReader.c -o ndpiReader $(LIB)

clean:
	\/bin/rm -f ndpiReader
