#!/bin/sh

if [ -z $ACLOCAL ]; then
	ACLOCAL=aclocal-1.7
fi
if [ -z $AUTOCONF ]; then 
	AUTOCONF=autoconf-2.57
fi
if [ -z $AUTOHEADER ]; then
	AUTOHEADER=autoheader-2.57
fi
rm -rf autom4te-2.53.cache
$ACLOCAL -I m4
$AUTOHEADER
$AUTOCONF
touch stamp-h.in
