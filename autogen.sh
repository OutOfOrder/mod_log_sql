#!/bin/sh

if [ -z $ACLOCAL ]; then
	ACLOCAL=aclocal
fi
if [ -z $AUTOCONF ]; then 
	AUTOCONF=autoconf
fi
if [ -z $AUTOHEADER ]; then
	AUTOHEADER=autoheader
fi
rm -rf autom4te.cache
$ACLOCAL -I m4
$AUTOHEADER
libtoolize -c --force
$AUTOCONF
touch stamp-h.in
