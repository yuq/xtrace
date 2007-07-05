#!/bin/sh
set -e

configindir="."
if [ "x$1" = "x--chdir" ] ; then
	shift
	configindir="$1"
	shift
fi

aclocal
autoheader
automake -a -c
autoconf

curdir="$(pwd)"
mkdir -p -- "$configindir"
cd "$configindir" || exit 1
"$curdir"/configure --enable-maintainer-mode CFLAGS="-Wall -O2 -g -Wmissing-prototypes -Wstrict-prototypes -W -DSTUPIDCC=1"
