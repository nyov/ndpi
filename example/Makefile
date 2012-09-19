INC=-I../src/include/
LIB=../src/lib/.libs/libndpi.a -lpcap

pcapReader: pcapReader.c Makefile
	gcc -g $(INC) pcapReader.c -o pcapReader $(LIB)