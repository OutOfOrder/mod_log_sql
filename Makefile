# $Id: Makefile,v 1.1 2001/11/28 05:26:54 helios Exp $

# Verify that this points to the right place...
APACHEDIR = /usr/local/src/apache_1.3.22/src

# Verify that this include directory is correct for you...
CFLAGS    = -fpic -O2 -Wall -I/usr/local/Apache/include

# ---------------------------------------------------------
# You shouldn't have to touch below here!

CC        = gcc
DEFS      = -DSHARED_MODULE  
INSTALL   = /usr/bin/install -m 664

all: mod_log_mysql.o

mod_log_mysql.o:	mod_log_mysql.c
			$(CC) ${CFLAGS} ${DEFS} -c mod_log_mysql.c

install: all
	$(INSTALL) mod_log_mysql.o ${APACHEDIR}/mod_log_mysql.o

distro: all
	cd ..; tar zcf mod_log_mysql.tar.gz mod_log_mysql/; $(INSTALL) mod_log_mysql.tar.gz /usr/local/Apache/html/mod_log_mysql/; rm -f mod_log_mysql.tar.gz
	
clean:
	rm -f *.o *~
