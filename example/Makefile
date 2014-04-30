INC=-I../src/ndpi/include/
LIB=../src/ndpi/lib/.libs/libndpi.a -lpcap
FLAGS=-g #-fno-color-diagnostics
example_ndping: example_ndping.c Makefile ../src/ndpi/lib/.libs/libndpi.a
	gcc $(FLAGS) $(INC) example_ndping.c -o example_ndping $(LIB) -lpthread -std=c99 -D_BSD_SOURCE

clean:
	\/bin/rm -f example_ndping
