#!/bin/sh
aclocal
autoheader
automake -a -c
autoconf
./configure --enable-maintainer-mode CFLAGS="-Wall -O2 -g -Wmissing-prototypes -Wstrict-prototypes -W -DSTUPIDCC=1"
