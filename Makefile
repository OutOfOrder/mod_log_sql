# $Id: Makefile,v 1.9 2002/04/21 23:01:52 helios Exp $
MLMVERS = 1.16

# Where you unpacked your Apache tarball -- the source.
APACHESOURCE = /usr/local/src/apache_1.3.22

# Where Apache [got|will get] installed
APACHEINST   = /usr/local/Apache

# Set the WANT_SSL_LOGGING define in mod_log_mysql.c if you want to log SSL
# info, or #undef it if you don't.  Then use the first CFLAGS if you *do*
# WANT_SSL_LOGGING, and confirm the paths.
#
# Modify "/usr/local/ssl/include" to where YOUR openssl/*.h files are,
# Modify "/usr/include/db1" to where YOUR ndbm.h can be found,
# Modify "/usr/local/src/apache_1.3.22/src/modules/ssl" to where YOUR mod_ssl.h can be found.
#
# How to find your directories:
#
# $ locate x509.h
# /usr/local/ssl/include/openssl/x509.h
# ^^^^^^^^^^^^^^^^^^^^^^
#
# $ locate ndbm.h
# /usr/include/db1/ndbm.h
# ^^^^^^^^^^^^^^^^
#
# $ locate mod_ssl.h
# /usr/local/src/apache_1.3.22/src/modules/ssl/mod_ssl.h
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

CFLAGS    = -fpic -O2 -Wall -I${APACHEINST}/include -I/usr/local/ssl/include -I/usr/include/db1 -I${APACHESOURCE}/src/modules/ssl

# Use this CFLAGS if you don't WANT_SSL_LOGGING:
#CFLAGS    = -fpic -O2 -Wall -I${APACHEINST}/include


# ---------------------------------------------------------
# You shouldn't have to touch below here.

CC        = gcc
INSTALL   = /usr/bin/install -m 664

all: mod_log_mysql.o

mod_log_mysql.o:	mod_log_mysql.c Makefile
	$(CC) ${CFLAGS} -c mod_log_mysql.c
			
install: all
	$(INSTALL) -d -m 755 ${APACHESOURCE}/src/modules/sql
	$(INSTALL) mod_log_mysql.c ${APACHESOURCE}/src/modules/sql/mod_log_mysql.c
	$(INSTALL) Makefile ${APACHESOURCE}/src/modules/sql/Makefile
	$(INSTALL) mod_log_mysql.o ${APACHESOURCE}/src/modules/sql/mod_log_mysql.o

distro: all
	cp -f INSTALL ${APACHEINST}/html/mod_log_mysql/
	cp -f README ${APACHEINST}/html/mod_log_mysql/
	cp -f CHANGELOG ${APACHEINST}/html/mod_log_mysql/
	cd ..; tar zcf mod_log_mysql-${MLMVERS}.tar.gz --exclude mod_log_mysql/CVS mod_log_mysql/; $(INSTALL) mod_log_mysql-${MLMVERS}.tar.gz ${APACHEINST}/html/mod_log_mysql/; rm -f mod_log_mysql-${MLMVERS}.tar.gz
	rm -f ${APACHEINST}/html/mod_log_mysql/mod_log_mysql.tar.gz 
	ln -s mod_log_mysql-${MLMVERS}.tar.gz ${APACHEINST}/html/mod_log_mysql/mod_log_mysql.tar.gz

clean:
	rm -f *.o *~
