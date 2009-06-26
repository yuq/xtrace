bin_PROGRAMS = xtrace xtraceng

CFLAGS ?= -g -O2
AM_CPPFLAGS = @CPPFLAGS@ -Wall -DPKGDATADIR='"$(pkgdatadir)"'
# for authdata.c: -I/usr/X11R6/include -DNeedFunctionPrototypes

xtrace_CPPFLAGS = $(AM_CPPFLAGS) -DOLDSTYLE=1
xtrace_SOURCES = main.c x11common.c x11client.c x11server.c parse.c copyauth.c atoms.c
# authdata.c
xtrace_LDFLAGS = -Wl,-z,defs
# for authdata.c add:  -L/usr/X11R6/lib -lX11 -lXext

xtraceng_SOURCES = main.c x11common.c x11client.c x11server.c parse.c copyauth.c atoms.c translate.c stringlist.c
xtraceng_LDFLAGS = -Wl,-z,defs

noinst_HEADERS = xtrace.h xinput.inc xkb.inc xinerama.inc requests.inc events.inc shape.inc bigrequest.inc render.inc randr.inc mitshm.inc xf86vidmode.inc xf86bigfont.inc dpms.inc saver.inc fixes.inc damage.inc glx.inc parse.h stringlist.h translate.h

dist_man_MANS = xtrace.1

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/configure $(srcdir)/install-sh $(srcdir)/stamp-h.in $(srcdir)/aclocal.m4 $(srcdir)/mkinstalldirs $(srcdir)/missing $(srcdir)/config.h.in $(srcdir)/depcomp

dist_pkgdata_DATA = all.proto bigfont.proto bigrequest.proto damage.proto dpms.proto errors.proto events.proto fixes.proto glx.proto mitshm.proto randr.proto render.proto requests.proto saver.proto shape.proto vidmode.proto xinerama.proto xinput.proto xkb.proto

EXTRA_DIST = autogen.sh config.h.in

distclean-local:
	-rm -rf $(srcdir)/autom4te.cache
maintainer-clean-local:
	-rm -rf $(srcdir)/ac
