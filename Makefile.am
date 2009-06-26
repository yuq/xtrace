bin_PROGRAMS = xtrace

CFLAGS ?= -g -O2
AM_CPPFLAGS = @CPPFLAGS@ -Wall -DPKGDATADIR='"$(pkgdatadir)"'

xtrace_SOURCES = main.c x11common.c x11client.c x11server.c parse.c copyauth.c atoms.c translate.c stringlist.c
xtrace_LDFLAGS = -Wl,-z,defs

noinst_HEADERS = xtrace.h parse.h stringlist.h translate.h

dist_man_MANS = xtrace.1

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/configure $(srcdir)/stamp-h.in $(srcdir)/aclocal.m4 $(srcdir)/config.h.in

dist_pkgdata_DATA = all.proto bigfont.proto bigrequest.proto damage.proto dpms.proto errors.proto events.proto fixes.proto glx.proto mitshm.proto randr.proto render.proto requests.proto saver.proto shape.proto vidmode.proto xinerama.proto xinput.proto xkb.proto

distclean-local:
	-rm -rf $(srcdir)/autom4te.cache
maintainer-clean-local:
	-rm -rf $(srcdir)/ac
