bin_PROGRAMS = xtrace
# decodexnumbers

CFLAGS ?= -g -O2
AM_CPPFLAGS = @CPPFLAGS@ -Wall
# for authdata.c: -I/usr/X11R6/include -DNeedFunctionPrototypes

xtrace_SOURCES = main.c x11common.c x11client.c x11server.c parse.c copyauth.c atoms.c
# authdata.c
xtrace_LDFLAGS = -Wl,-z,defs
# for authdata.c add:  -L/usr/X11R6/lib -lX11 -lXext

# decodexnumbers_SOURCES = masktosymbols.c
# decodexnumbers_LDFLAGS = -Wl,-z,syms

noinst_HEADERS = xtrace.h xinerama.inc requests.inc events.inc shape.inc bigrequest.inc render.inc randr.inc mitshm.inc xf86vidmode.inc xf86bigfont.inc

man_MANS = xtrace.1

MAINTAINERCLEANFILES = Makefile.in configure install-sh stamp-h.in aclocal.m4 mkinstalldirs missing config.h.in autom4te.cache config.guess config.sub depcomp

EXTRA_DIST = autogen.sh config.h.in xtrace.1

distclean-local:
	-rm -rf autom4te.cache
