bin_PROGRAMS = example_ndping

AM_CPPFLAGS = -I$(top_srcdir)/src/ndpi/include @PCAP_INC@ -D_BSD_SOURCE
AM_CFLAGS = @PTHREAD_CFLAGS@ -std=c99

LDADD = $(top_builddir)/src/ndpi/lib/libndpi.la @PTHREAD_LIBS@ @PCAP_LIB@
AM_LDFLAGS = -static

example_ndping_SOURCES = example_ndping.c
