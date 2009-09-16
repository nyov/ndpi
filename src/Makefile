

compileparam = -O2 -g -pipe -Wall -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wparentheses -Wformat -Winline -Wreturn-type -fPIC -Wmissing-prototypes -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -maccumulate-outgoing-args -Wno-sign-compare -fno-asynchronous-unwind-tables -fomit-frame-pointer -Werror -D_FILE_OFFSET_BITS=64


all: library demo_program

library:
	cd ./lib && $(CC) -c -I ../include $(compileparam) *.c
	cd ./lib/protocols && $(CC) -c -I .. -I ../../include $(compileparam) *.c

	ar rcs ./libOpenDPI.a ./lib/*.o ./lib/protocols/*.o

demo_program: OpenDPI_demo.c library
	$(CC) $(compileparam) -I include OpenDPI_demo.c libOpenDPI.a -lpcap -o OpenDPI_demo

clean:
	rm -rf *.a OpenDPI_demo libOpenDPI.a
	cd ./lib && rm -rf *.o
	cd ./lib/protocols && rm -rf *.o
