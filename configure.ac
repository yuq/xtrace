dnl
dnl Process this file with autoconf to produce a configure script
dnl

AC_INIT(xtrace, 1.2.0, brlink@debian.org)
AC_CONFIG_SRCDIR(main.c)
AC_CONFIG_AUX_DIR(ac)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([-Wall -Werror])

AM_MAINTAINER_MODE
AC_GNU_SOURCE

if test "${CFLAGS:+set}" != set ; then
	CFLAGS="-Wall -O2 -g -Wmissing-prototypes -Wstrict-prototypes -Wshadow"
fi

AC_PROG_CC_C99
AC_PROG_INSTALL

AC_CACHE_CHECK([Checking for _POSIX_TIMERS and _POSIX_MONOTONIC_CLOCK],[ac_cv_monotonic_clock],
[AC_PREPROC_IFELSE(AC_LANG_PROGRAM([[
#include <unistd.h>
#include <time.h>
]],[[
#ifdef _POSIX_TIMERS
#if defined(_POSIX_MONOTONIC_CLOCK) && _POSIX_MONOTONIC_CLOCK >= 0
1
#else
#error _POSIX_MONOTONIC_CLOCK not defined, or not positive, not using clock_gettime
#endif
#else
#error _POSIX_TIMERS not defined, not using clock_gettime
#endif
]]), [ac_cv_monotonic_clock=yes], [ac_cv_monotonic_clock=no])])

if test $ac_cv_monotonic_clock = yes ; then
	AC_DEFINE([HAVE_MONOTONIC_CLOCK], 1, [Define if clock_gettime(CLOCK_MONOTONIC) should work])
	AC_CHECK_LIB(rt, clock_gettime, [], [AC_MSG_ERROR([_POSIX_TIMERS suggests clock_gettime should work but it seems not to work, though])])
fi

AC_CHECK_FUNCS([strndup asprintf socket])
if test $ac_cv_func_socket = no; then
	AC_CHECK_LIB(socket, socket, [AC_DEFINE(HAVE_SOCKET)
LIBS="$LIBS -lsocket -lnsl"; break],[AC_MSG_ERROR([Could not find socket library function])])
fi
AC_CHECK_FUNC([getaddrinfo],,[AC_MSG_ERROR([Could not find getaddrinfo library function])])

dnl AC_CHECK_HEADER(X11/X.h,[],[AC_MSG_ERROR([Could not find X11/X.h])])
dnl AC_CHECK_HEADER(X11/Xlib.h,[],[AC_MSG_ERROR([Could not find X11/Xlib.h])])
dnl AC_CHECK_HEADER(X11/extensions/security.h,[],[AC_MSG_ERROR([Could not find X11/extensions/secruity.h])],[#include <X11/Xlib.h>])

AC_OUTPUT(Makefile)
