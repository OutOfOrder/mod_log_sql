# $Id: Makefile,v 1.2 2001/12/03 19:54:02 helios Exp $

# Verify that this points to the right place...
APACHEDIR = /usr/local/src/apache_1.3.22

# Use the first one if you want mod_log_mysql to be able to log
# SSL variables like keysize or cipher.  Use the second one if
# you don't use SSL or don't care to log it.
DEFS      = -DWANT_SSL_LOGGING
#DEFS      =

# Use this one if you do WANT_SSL_LOGGING, and confirm the last two paths.
# Make "/usr/local/ssl/include" point to where your openssl/*.h files are,
# and make "/usr/include/db1" point to where ndbm.h can be found.
#
# How to find your directories:
#
# $ locate http_core.h
# /usr/local/Apache/include/http_core.h
#
# $ locate x509.h
# /usr/local/ssl/include/openssl/x509.h
#
# $ locate ndbm.h
# /usr/include/db1/ndbm.h

CFLAGS    = -fpic -O2 -Wall -I/usr/local/Apache/include -I/usr/local/ssl/include -I/usr/include/db1

# Use this one if you don't WANT_SSL_LOGGING:

#CFLAGS    = -fpic -O2 -Wall -I/usr/local/Apache/include


# ---------------------------------------------------------
# You shouldn't have to touch below here.

CC        = gcc
INSTALL   = /usr/bin/install -m 664

all: mod_log_mysql.o

mod_log_mysql.o:	mod_log_mysql.c Makefile
			$(CC) ${CFLAGS} ${DEFS} -c mod_log_mysql.c

install: all
	$(INSTALL) mod_log_mysql.o ${APACHEDIR}/src/mod_log_mysql.o

distro: all
	cd ..; tar zcf mod_log_mysql.tar.gz mod_log_mysql/; $(INSTALL) mod_log_mysql.tar.gz /usr/local/Apache/html/mod_log_mysql/; rm -f mod_log_mysql.tar.gz
	
clean:
	rm -f *.o *~
