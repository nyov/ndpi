bin_PROGRAMS = ndpiReader

AM_CPPFLAGS = -I$(top_srcdir)/src/include -I third-party/json-c
AM_CFLAGS = @PTHREAD_CFLAGS@

LDADD = $(top_builddir)/src/lib/libndpi.la third-party/json-c/libjson-c.la @PTHREAD_LIBS@
LDFLAGS = -static

ndpiReader_SOURCES = ndpiReader.c

# Explictely state that to build ndpiReader.o we first need json_config.h.
ndpiReader.o: third-party/json-c/libjson-c.la

third-party/json-c/libjson-c.la:
	cd third-party/json-c && ./configure
	cd third-party/json-c && make libjson-c.la

clean-local:
	cd third-party/json-c && make clean

distclean-local:
	cd third-party/json-c && make distclean

EXTRA_DIST = third-party
