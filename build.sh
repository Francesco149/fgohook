#!/bin/sh

CFLAGS="-fPIC -Wall -O0 $CFLAGS"
LDFLAGS="-shared -llog -ldl $LDFLAGS"
[ -z "$CC" ] &&
  echo "please set CC to your android toolchain compiler" && exit 1
$CC $CFLAGS fgohook.c $LDFLAGS -o libmain.so
