AC_INIT([nDPI], [1.4.0])
AC_CONFIG_SRCDIR([src/include/ndpi_protocols.h])

AM_INIT_AUTOMAKE([-Wall])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_LIBTOOL

AC_PROG_CC
AC_PROG_INSTALL

LT_INIT

case "$host:$CC" in
    *darwin* )
        RES=`gcc -Wall -fno-color-diagnostics src/lib/ndpi_main.c 2>&1 | grep "unrecognized command line option "|wc -l`
	if test $RES -eq 0; then
	        PLATFORM_DEPENDENT="-fno-color-diagnostics"
	fi
	;;
esac

AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h unistd.h])

AC_CONFIG_FILES([Makefile
		src/lib/Makefile
		src/include/Makefile
		libndpi.pc
		])

AC_CONFIG_HEADERS(config.h)
AC_SUBST(PLATFORM_DEPENDENT)

AC_OUTPUT
