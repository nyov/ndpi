INC=-I../src/include/
LIB=../src/lib/.libs/libndpi.a -lpcap
FLAGS=-O2 -g
pcapReader: pcapReader.c Makefile ../src/lib/.libs/libndpi.a
	gcc $(FLAGS) $(INC) pcapReader.c -o pcapReader $(LIB)

clean:
	\/bin/rm -f pcapReader
