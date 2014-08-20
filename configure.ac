AC_INIT([libndpi], [1.5.0])

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

PCAP_HOME=$HOME/PF_RING/userland/libpcap
if test -f $PCAP_HOME/libpcap.a; then :
     echo "Using libpcap from $PCAP_HOME"
     PCAP_INC="-I $PCAP_HOME"
     PCAP_LIB="$PCAP_HOME/libpcap.a $HOME/PF_RING/userland/lib/libpfring.a -lnuma"

     AC_CHECK_LIB([rt], [clock_gettime],   [PCAP_LIB="$PCAP_LIB -lrt"])
     AC_CHECK_LIB([nl], [nl_handle_alloc], [PCAP_LIB="$PCAP_LIB -lnl"])
else
    AC_CHECK_LIB([pcap], [pcap_open_live], [PCAP_LIB="-lpcap"])

     if test $ac_cv_lib_pcap_pcap_open_live = "no"; then :
       echo ""
       echo "ERROR: Missing libpcap(-dev) library required to compile the example application"
       echo "ERROR: Please install it and try again"
       exit
   fi
fi

AC_ARG_WITH([system-json-c],
            [AS_HELP_STRING([--with-system-json-c],
                            [use system libjson-c (default is no)])])
if test "x$with_system_json_c" = "xyes"; then
    PKG_CHECK_MODULES([JSON_C], [json-c])
else
    JSON_C_CFLAGS=-Ithird-party/json-c
    JSON_C_LIBS=third-party/json-c/libjson-c.la
fi

AC_ARG_ENABLE([examples-dynamic-linking],
             [AS_HELP_STRING([--enable-examples-dynamic-linking],
                             [dynamically link examples against libndpi (default is no)])])

AM_CONDITIONAL(JSON_C_SYSTEM, [test "x$with_system_json_c" = "xyes"])
AM_CONDITIONAL(EXAMPLES_DYNAMIC_LINK, [test "x$enable_examples_dynamic_linking" = "xyes"])  

AC_CONFIG_FILES([Makefile src/lib/Makefile example/Makefile libndpi.pc])
AC_CONFIG_HEADERS(config.h)
AC_SUBST(JSON_C_CFLAGS)
AC_SUBST(JSON_C_LIBS)
AC_SUBST(JSON_C_SYSTEM)
AC_SUBST(SVN_RELEASE)
AC_SUBST(SVN_DATE)
AC_SUBST(PCAP_INC)
AC_SUBST(PCAP_LIB)

AC_OUTPUT
