# $Id: Makefile,v 1.11 2002/09/04 18:46:00 helios Exp $
MLMVERS = 1.17

# Where you unpacked your Apache tarball -- the source.
APACHESOURCE = /usr/local/src/apache_1.3.26

# Where Apache [got|will get] installed
APACHEINST   = /usr/local/Apache

# Do you want to log SSL information?
# Yes?
#      - #define WANT_SSL_LOGGING in mod_log_sql.c
#      - pick (A) below
# No?
#      - #undef WANT_SSL_LOGGING in mod_log_sql.c
#      - pick (B) below


# (A)
#
# Modify "/usr/include/mysql" to where YOUR mysql.h can be found,
# Modify "/usr/local/ssl/include" to where YOUR openssl/*.h files are,
# Modify "/usr/include/db1" to where YOUR ndbm.h can be found,
# Modify "/usr/local/src/apache_1.3.22/src/modules/ssl" to where YOUR mod_ssl.h can be found.
#
# How to find your directories:
#
# $ locate mysql.h
# /usr/include/mysql/mysql.h
# ^^^^^^^^^^^^^^^^^^
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
# Now uncomment this CFLAGS and comment out the one further down:

CFLAGS    = -fpic -O2 -Wall -I${APACHEINST}/include -I/usr/include/mysql -I/usr/local/ssl/include -I/usr/include/db1 -I${APACHESOURCE}/src/modules/ssl

# (B)
#
# Modify "/usr/include/mysql" to where YOUR mysql.h can be found,
#
# How to find your directories:
#
# $ locate mysql.h
# /usr/include/mysql/mysql.h
# ^^^^^^^^^^^^^^^^^^
#
# Comment out CFLAGS above and uncomment CFLAGS below:

#CFLAGS    = -fpic -O2 -Wall -I${APACHEINST}/include -I/usr/include/mysql


# ---------------------------------------------------------
# You shouldn't have to touch below here.

CC        = gcc
INSTALL   = /usr/bin/install -m 664

all: mod_log_sql.o

mod_log_sql.o:	mod_log_sql.c Makefile
	$(CC) ${CFLAGS} -c mod_log_sql.c
			
install: all
	$(INSTALL) -d -m 755 ${APACHESOURCE}/src/modules/sql
	$(INSTALL) mod_log_sql.c ${APACHESOURCE}/src/modules/sql/mod_log_sql.c
	$(INSTALL) Makefile ${APACHESOURCE}/src/modules/sql/Makefile
	$(INSTALL) mod_log_sql.o ${APACHESOURCE}/src/modules/sql/mod_log_sql.o

distro: all
	cp -f INSTALL ${APACHEINST}/html/mod_log_sql/
	cp -f README ${APACHEINST}/html/mod_log_sql/
	cp -f CHANGELOG ${APACHEINST}/html/mod_log_sql/
	cd ..; tar zcf mod_log_sql-${MLMVERS}.tar.gz --exclude mod_log_sql/CVS mod_log_sql/; $(INSTALL) mod_log_sql-${MLMVERS}.tar.gz ${APACHEINST}/html/mod_log_sql/; rm -f mod_log_sql-${MLMVERS}.tar.gz
	rm -f ${APACHEINST}/html/mod_log_sql/mod_log_sql.tar.gz 
	ln -s mod_log_sql-${MLMVERS}.tar.gz ${APACHEINST}/html/mod_log_sql/mod_log_sql.tar.gz

clean:
	rm -f *.o *~
