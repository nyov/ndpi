INC=-I../src/include/
LIB=../src/lib/.libs/libndpi.a -lpcap

pcapReader: pcapReader.c Makefile ../src/lib/.libs/libndpi.a
	gcc -g $(INC) pcapReader.c -o pcapReader $(LIB)

clean:
	\/bin/rm -f pcapReader
