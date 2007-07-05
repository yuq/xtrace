dnl
dnl Process this file with autoconf to produce a configure script
dnl

AC_INIT(main.c)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE(xtrace,0.7.0)

AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_INSTALL

AC_DEFINE([_GNU_SOURCE],[1],[To tell glibc to make strndup visible])
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
