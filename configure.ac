dnl
dnl Process this file with autoconf to produce a configure script
dnl

AC_INIT(xtrace, 1.1.0, brlink@debian.org)
AC_CONFIG_SRCDIR(main.c)
AC_CONFIG_AUX_DIR(ac)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([-Wall -Werror])

AM_MAINTAINER_MODE
AC_GNU_SOURCE

AC_PROG_CC
AC_PROG_INSTALL

AC_CHECK_FUNCS([strndup])
AC_CHECK_FUNCS([asprintf])

AC_CHECK_FUNCS(socket)
if test $ac_cv_func_socket = no; then
	AC_CHECK_LIB(socket, socket, [AC_DEFINE(HAVE_SOCKET)
LIBS="$LIBS -lsocket -lnsl"; break],[AC_MSG_ERROR([Could not find socket library function])])
fi
AC_CHECK_FUNC([getaddrinfo],,[AC_MSG_ERROR([Could not find getaddrinfo library function])])

dnl AC_CHECK_HEADER(X11/X.h,[],[AC_MSG_ERROR([Could not find X11/X.h])])
dnl AC_CHECK_HEADER(X11/Xlib.h,[],[AC_MSG_ERROR([Could not find X11/Xlib.h])])
dnl AC_CHECK_HEADER(X11/extensions/security.h,[],[AC_MSG_ERROR([Could not find X11/extensions/secruity.h])],[#include <X11/Xlib.h>])

AC_OUTPUT(Makefile)
