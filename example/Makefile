#PFRINGDIR=../../../PF_RING
#LIBPFRING=${PFRINGDIR}/userland/lib/libpfring.a -lnuma
#PCAPDIR=${PFRINGDIR}/userland/libpcap-1.1.1-ring
#LIBPCAP=${PCAPDIR}/libpcap.a

LIBPCAP=-lpcap

INC=-I../src/include/
LIB=../src/lib/.libs/libndpi.a ${LIBPCAP} ${LIBPFRING}
FLAGS=-O2 #-g #-fno-color-diagnostics
pcapReader: pcapReader.c Makefile ../src/lib/.libs/libndpi.a
	gcc $(FLAGS) $(INC) pcapReader.c -o pcapReader $(LIB) -lpthread

clean:
	\/bin/rm -f pcapReader
