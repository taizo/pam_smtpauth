#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([pam_smtpauth], [0.9.8], [taizo.ito@hde.co.jp])
AC_CONFIG_SRCDIR([src/pam_smtpauth.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, inet_ntoa)
# FIXME: Replace `main' with a function in `-lpam':
AC_CHECK_LIB(pam, pam_sm_authenticate, [LIBS="$LIBS -lpam"])
# FIXME: Replace `main' with a function in `-lpam_misc':
AC_CHECK_LIB([pam_misc], [main], [LIBS="$LIBS -lpam_misc"])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h syslog.h unistd.h])

AC_ARG_ENABLE(debug,
[  --enable-debug          turn on debugging [[default=no]]],
[\
case "${enableval}" in
 yes) enable_debug=yes ;;
 no)  enable_debug=no ;;
 *)   AC_MSG_ERROR(bad value for --enable-debug) ;;
esac],
enable_debug=no)
if test x"${enable_debug}" = x"yes"; then
  AC_DEFINE(DEBUG, 1, [Define to 1 if you want to debug])
fi

dnl Check for OpenSSL
AC_ARG_ENABLE(ssl,
	[  --enable-ssl            Enable SSL support using OpenSSL [default=no]],
	[ac_cv_enable_ssl=$enableval], [ac_cv_enable_ssl=no])
AC_MSG_CHECKING([whether to use OpenSSL])
if test $ac_cv_enable_ssl = yes; then
	AC_MSG_RESULT(yes)
	AC_MSG_CHECKING([if openssl is available])
	LIBS="$LIBS -lssl -lcrypto"
	AC_TRY_LINK([
#include <openssl/opensslv.h>
],	[ return OPENSSL_VERSION_NUMBER; ],
	[ AC_MSG_RESULT(yes)
          AC_DEFINE(USE_SSL, 1, [Define for OpenSSL]) ],
	[ AC_MSG_RESULT(no)
	  LIBS="$ac_save_LIBS"
	  ac_cv_enable_ssl=no ])
else
	AC_MSG_RESULT(no)
fi

AC_ARG_WITH(krb5-dir,
    AC_HELP_STRING([--with-krb5-dir=PATH], [KRB5 lib/include root]),
[\
case "${withval}" in
   no) ;;
   *)
     CPPFLAGS="$CPPFLAGS -I${withval}/include"
     LDFLAGS="$LDFLAGS -L${withval}/lib"
     ;;
esac ])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([alarm gethostbyname getpass inet_ntoa memset socket strchr strdup strncasecmp strpbrk strstr])

AC_CONFIG_FILES([
pam_smtpauth.spec
Makefile
src/Makefile
tools/Makefile
])
AC_OUTPUT
