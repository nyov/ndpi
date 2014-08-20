bin_PROGRAMS = ndpiReader

AM_CPPFLAGS = -I$(top_srcdir)/src/include @JSON_C_CFLAGS@ @PCAP_INC@
AM_CFLAGS = @PTHREAD_CFLAGS@

LDADD = $(top_builddir)/src/lib/libndpi.la @JSON_C_LIBS@ @PTHREAD_LIBS@ @PCAP_LIB@
if !EXAMPLES_DYNAMIC_LINK
AM_LDFLAGS = -static
endif

ndpiReader_SOURCES = ndpiReader.c

if !JSON_C_SYSTEM 
# Explicitely state that to build ndpiReader.o we first need json_config.h.
ndpiReader.o: third-party/json-c/libjson-c.la

third-party/json-c/libjson-c.la:
	cd third-party/json-c && ./configure
	cd third-party/json-c && make libjson-c.la

clean-local:
	cd third-party/json-c && make clean

distclean-local:
	cd third-party/json-c && make distclean

endif

EXTRA_DIST = third-party
