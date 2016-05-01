bin_PROGRAMS = xtrace

AM_CPPFLAGS = -DPKGDATADIR='"$(pkgdatadir)"'

xtrace_SOURCES = main.c x11common.c x11client.c x11server.c parse.c copyauth.c atoms.c translate.c stringlist.c

noinst_HEADERS = xtrace.h parse.h stringlist.h translate.h

dist_man_MANS = xtrace.1

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/configure $(srcdir)/stamp-h.in $(srcdir)/aclocal.m4 $(srcdir)/config.h.in

dist_pkgdata_DATA = all.proto bigfont.proto bigrequest.proto damage.proto dpms.proto dri2.proto errors.proto events.proto fixes.proto genericevents.proto glx.proto mitshm.proto randr.proto render.proto requests.proto saver.proto setup.proto shape.proto sync.proto vidmode.proto xinerama.proto xinput.proto xkb.proto xvideo.proto composite.proto dga.proto dri3.proto present.proto

distclean-local:
	-rm -rf $(srcdir)/autom4te.cache
maintainer-clean-local:
	-rm -rf $(srcdir)/ac
