# $Id: Makefile,v 1.5 2002/01/15 18:40:14 helios Exp $
MLMVERS = 1.13

# Where you unpacked your Apache tarball -- the source.
APACHESOURCE = /usr/local/src/apache_1.3.22

# Where Apache [got|will get] installed
APACHEINST   = /usr/local/Apache

# Use the first DEFS line if you want mod_log_mysql to be able to log SSL
# variables like keysize or cipher.  Use the second one if you don't use SSL
# or don't care to log it.
#
# If your MySQL db is running on the same machine as Apache, modify the
# MYSQLSOCKET path to point to your MySQL socket.  This define has no effect
# if your MySQL machine is a networked (TCP/IP) machine.

DEFS      = -DMYSQLSOCKET="\"/var/lib/mysql/mysql.sock\"" -DWANT_SSL_LOGGING
#DEFS      = -DMYSQLSOCKET="\"/var/lib/mysql/mysql.sock\""

# Use the first CFLAGS if you *do* WANT_SSL_LOGGING, and confirm the paths.
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
	$(CC) ${CFLAGS} ${DEFS} -c mod_log_mysql.c
			
install: all
	$(INSTALL) mod_log_mysql.o ${APACHESOURCE}/src/mod_log_mysql.o

distro: all
	cp -f INSTALL ${APACHEINST}/html/mod_log_mysql/
	cp -f README ${APACHEINST}/html/mod_log_mysql/
	cp -f CHANGELOG ${APACHEINST}/html/mod_log_mysql/
	cd ..; tar zcf mod_log_mysql-${MLMVERS}.tar.gz --exclude mod_log_mysql/CVS mod_log_mysql/; $(INSTALL) mod_log_mysql-${MLMVERS}.tar.gz ${APACHEINST}/html/mod_log_mysql/; rm -f mod_log_mysql-${MLMVERS}.tar.gz
	
clean:
	rm -f *.o *~
