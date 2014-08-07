AC_INIT([libndpi], [1.4.99])

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects])

LT_INIT

AC_PROG_CC
AX_PTHREAD

SVN_RELEASE=`svn info . | grep "^Revision"|cut -d " " -f 2`
AC_DEFINE_UNQUOTED(NDPI_SVN_RELEASE, "r${SVN_RELEASE}", [SVN Release])
SVN_DATE=`svn info . | grep "^Last Changed Date"|cut -d " " -f 4-`
AC_DEFINE_UNQUOTED(NDPI_SVN_DATE, "${SVN_DATE}", [Last SVN change])

AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h unistd.h])

AC_CHECK_LIB([pcap], [pcap_open_live])

if test $ac_cv_lib_pcap_pcap_open_live = "no"; then :
   PCAP_HOME=$HOME/PF_RING/userland/libpcap
   if test -f $PCAP_HOME/libpcap.a; then :
     echo "Found $PCAP_HOME"
     PCAP_INC="-I $PCAP_HOME"
     PCAP_LIB="$PCAP_HOME/libpcap.a $HOME/PF_RING/userland/lib/libpfring.a -lnuma"
   else
     echo ""
     echo "ERROR: Missing libpcap(-dev) library required to compile the example application"
     echo "ERROR: Please install it and try again"
     exit
   fi
else
  PCAP_LIB="-lpcap"
fi

AC_CONFIG_FILES([Makefile src/lib/Makefile example/Makefile libndpi.pc])
AC_CONFIG_HEADERS(config.h)
AC_SUBST(SVN_RELEASE)
AC_SUBST(SVN_DATE)
AC_SUBST(PCAP_INC)
AC_SUBST(PCAP_LIB)

AC_OUTPUT
